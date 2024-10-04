/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/ls-routing-protocol.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-packet-info-tag.h"
#include "ns3/ipv4-route.h"
#include "ns3/log.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/test-result.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include <ctime>
#include <tuple>
#include <iostream>
#include <unordered_set>
#include <queue>
#include <algorithm>
#include <climits> 

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("LSRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED(LSRoutingProtocol);

/********** Miscellaneous constants **********/

/// Maximum allowed sequence number
#define LS_MAX_SEQUENCE_NUMBER 0xFFFF
#define LS_PORT_NUMBER 698

TypeId
LSRoutingProtocol::GetTypeId(void)
{
  static TypeId tid = TypeId("LSRoutingProtocol")
                          .SetParent<PennRoutingProtocol>()
                          .AddConstructor<LSRoutingProtocol>()
                          .AddAttribute("LSPort", "Listening port for LS packets", UintegerValue(5000),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_lsPort), MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_pingTimeout), MakeTimeChecker())
                          .AddAttribute("HelloTimeout", "Frequency for HELLO_REQ in milliseconds", TimeValue(MilliSeconds(1000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_helloTimeout), MakeTimeChecker())
                          .AddAttribute("LSTimeout", "Frequency for LS_FLOOD in milliseconds", TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_lsTimeout), MakeTimeChecker())
                          .AddAttribute("MaxTTL", "Maximum TTL value for LS packets", UintegerValue(16),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_maxTTL), MakeUintegerChecker<uint8_t>());
  return tid;
}

LSRoutingProtocol::LSRoutingProtocol()
    : m_auditPingsTimer(Timer::CANCEL_ON_DESTROY), m_helloTimer(Timer::CANCEL_ON_DESTROY), m_lsTimer(Timer::CANCEL_ON_DESTROY),
    m_networkChange(false)
{
  m_currentSequenceNumber = 0;
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting>();
}

LSRoutingProtocol::~LSRoutingProtocol() {}

void LSRoutingProtocol::DoDispose()
{
  if (m_recvSocket)
  {
    m_recvSocket->Close();
    m_recvSocket = 0;
  }

  // Close sockets
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    iter->first->Close();
  }
  m_socketAddresses.clear();

  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel();
  m_helloTimer.Cancel();
  m_lsTimer.Cancel();
  m_pingTracker.clear();

  // Clear Neighbor Table and Log
  m_neighborTable.clear();
  m_neighborLog.clear();

  // Clear Routing Table and m_validLSP
  m_routingTable.clear();
  m_validLSP.clear();

  PennRoutingProtocol::DoDispose();
}

void LSRoutingProtocol::SetMainInterface(uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress(mainInterface, 0).GetLocal();
}

void LSRoutingProtocol::SetNodeAddressMap(std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void LSRoutingProtocol::SetAddressNodeMap(std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
LSRoutingProtocol::ResolveNodeIpAddress(uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find(nodeNumber);
  if (iter != m_nodeAddressMap.end())
  {
    return iter->second;
  }
  return Ipv4Address::GetAny();
}

std::string
LSRoutingProtocol::ReverseLookup(Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find(ipAddress);
  if (iter != m_addressNodeMap.end())
  {
    std::ostringstream sin;
    uint32_t nodeNumber = iter->second;
    sin << nodeNumber;
    return sin.str();
  }
  return "Unknown";
}

void LSRoutingProtocol::DoInitialize()
{

  if (m_mainAddress == Ipv4Address())
  {
    Ipv4Address loopback("127.0.0.1");
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
    {
      // Use primary address, if multiple
      Ipv4Address addr = m_ipv4->GetAddress(i, 0).GetLocal();
      if (addr != loopback)
      {
        m_mainAddress = addr;
        break;
      }
    }

    NS_ASSERT(m_mainAddress != Ipv4Address());
  }

  NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);

  bool canRunLS = false;
  // Create sockets
  for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
  {
    Ipv4Address ipAddress = m_ipv4->GetAddress(i, 0).GetLocal();
    if (ipAddress == Ipv4Address::GetLoopback())
      continue;

    // Create a socket to listen on all the interfaces
    if (m_recvSocket == 0)
    {
      m_recvSocket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
      m_recvSocket->SetAllowBroadcast(true);
      InetSocketAddress inetAddr(Ipv4Address::GetAny(), LS_PORT_NUMBER);
      m_recvSocket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this));
      if (m_recvSocket->Bind(inetAddr))
      {
        NS_FATAL_ERROR("Failed to bind() LS socket");
      }
      m_recvSocket->SetRecvPktInfo(true);
      m_recvSocket->ShutdownSend();
    }

    // Create socket on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    socket->SetAllowBroadcast(true);
    InetSocketAddress inetAddr(m_ipv4->GetAddress(i, 0).GetLocal(), m_lsPort);
    socket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this));
    if (socket->Bind(inetAddr))
    {
      NS_FATAL_ERROR("LSRoutingProtocol::DoInitialize::Failed to bind socket!");
    }
    socket->BindToNetDevice(m_ipv4->GetNetDevice(i));
    m_socketAddresses[socket] = m_ipv4->GetAddress(i, 0);
    canRunLS = true;
  }

  if (canRunLS)
  {
    AuditPings();
    SayHello();
    LSAdvertise();
    NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);
  }
}

void LSRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  // You can ignore this function
}

Ptr<Ipv4Route>
LSRoutingProtocol::RouteOutput(Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface,
                               Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput(packet, header, outInterface, sockerr);
  if (ipv4Route)
  {
    DEBUG_LOG("Found route to: " << ipv4Route->GetDestination() << " via next-hop: " << ipv4Route->GetGateway()
                                 << " with source: " << ipv4Route->GetSource() << " and output device "
                                 << ipv4Route->GetOutputDevice());
  }
  else
  {
    DEBUG_LOG("No Route to destination: " << header.GetDestination());
  }
  return ipv4Route;
}

bool LSRoutingProtocol::RouteInput(Ptr<const Packet> packet, const Ipv4Header &header, Ptr<const NetDevice> inputDev,
                                   UnicastForwardCallback ucb, MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                                   ErrorCallback ecb)
{
  Ipv4Address destinationAddress = header.GetDestination();
  Ipv4Address sourceAddress = header.GetSource();

  // Drop if packet was originated by this node
  if (IsOwnAddress(sourceAddress) == true)
  {
    return true;
  }

  // Check for local delivery
  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice(inputDev);
  if (m_ipv4->IsDestinationAddress(destinationAddress, interfaceNum))
  {
    if (!lcb.IsNull())
    {
      lcb(packet, header, interfaceNum);
      return true;
    }
    else
    {
      return false;
    }
  }

  // Check static routing table
  if (m_staticRouting->RouteInput(packet, header, inputDev, ucb, mcb, lcb, ecb))
  {
    return true;
  }

  DEBUG_LOG("Cannot forward packet. No Route to destination: " << header.GetDestination());
  return false;
}

void LSRoutingProtocol::BroadcastPacket(Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ptr<Packet> pkt = packet->Copy();
    Ipv4Address broadcastAddr = i->second.GetLocal().GetSubnetDirectedBroadcast(i->second.GetMask());
    i->first->SendTo(pkt, 0, InetSocketAddress(broadcastAddr, LS_PORT_NUMBER));
  }
}

void LSRoutingProtocol::ProcessCommand(std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin(); //make iterator over tokens
  std::string command = *iterator;
  if (command == "PING")
  {
    if (tokens.size() < 3)
    {
      ERROR_LOG("Insufficient PING params...");
      return;
    }  //from now on: parse ta tokens
    iterator++;  
    std::istringstream sin(*iterator);
    uint32_t nodeNumber;
    sin >> nodeNumber;
    iterator++;
    std::string pingMessage = *iterator; //receive ping msg
    Ipv4Address destAddress = ResolveNodeIpAddress(nodeNumber);
    if (destAddress != Ipv4Address::GetAny())
    {
      uint32_t sequenceNumber = GetNextSequenceNumber();
      TRAFFIC_LOG("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: "
                                               << pingMessage << " SequenceNumber: " << sequenceNumber);
      Ptr<PingRequest> pingRequest = Create<PingRequest>(sequenceNumber, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert(std::make_pair(sequenceNumber, pingRequest));
      Ptr<Packet> packet = Create<Packet>();
      LSMessage lsMessage = LSMessage(LSMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
      lsMessage.SetPingReq(destAddress, pingMessage); //calls function from ls msg
      packet->AddHeader(lsMessage); //calls function from packet
      BroadcastPacket(packet); //etsi kanw broadcast to ping to opoio einai mesa sto packet
    }
  }
  else if (command == "DUMP")
  {
    if (tokens.size() < 2)
    {
      ERROR_LOG("Insufficient Parameters!");
      return;
    }
    iterator++;
    std::string table = *iterator;
    if (table == "ROUTES" || table == "ROUTING")
    {
      DumpRoutingTable();
    }
    else if (table == "NEIGHBORS" || table == "neighborS")
    {
      DumpNeighbors();
    }
    else if (table == "LSA")
    {
      DumpLSA();
    }
  }
}

void LSRoutingProtocol::DumpLSA()
{
  STATUS_LOG(std::endl
             << "**************** LSA DUMP ********************" << std::endl
             << "Node\t\tNeighbor(s)");
  PRINT_LOG("");
}

void LSRoutingProtocol::DumpNeighbors()
{
  STATUS_LOG(std::endl
             << "**************** Neighbor List ********************" << std::endl
             << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");

  PRINT_LOG(std::to_string(m_neighborTable.size()));

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
  std::map<std::string, std::tuple<Ipv4Address, Ipv4Address>>::iterator it = m_neighborTable.begin();

  while (it != m_neighborTable.end())
  {
    // std::cout << "Key: " << it->first << ", Value: " << it->second << std::endl;
    PRINT_LOG(it->first << "\t\t\t" << std::get<0>(it->second) << "\t\t" << std::get<1>(it->second));
    checkNeighborTableEntry(stoi(it->first), std::get<0>(it->second), std::get<1>(it->second));
    ++it;
  }
  //  checkNeighborTableEntry();
}

void LSRoutingProtocol::DumpRoutingTable()
{
  STATUS_LOG(std::endl
             << "**************** Route Table ********************" << std::endl
             << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");

  PRINT_LOG("");

  // std::map<std::string, std::tuple<uint64_t, std::vector<Ipv4Address>>>::iterator it = m_validLSP.begin();

  // while (it != m_validLSP.end())
  // {
  //   PRINT_LOG("Node " << it->first << "\t\t" << "Sequence " << std::get<0>(it->second));
  //   for (Ipv4Address neighbor : std::get<1>(it->second)){
  //     // checkNeighborTableEntry(stoi(it->first), std::get<0>(it->second), std::get<1>(it->second));
  //     PRINT_LOG("\t\t" << ReverseLookup(neighbor) << "\t\t" << neighbor);
  //   }
  //   ++it;
  // }

  std::map<std::string, std::tuple<Ipv4Address, int>>::iterator it = m_routingTable.begin();

  while (it != m_routingTable.end())
  {
    if (std::get<1>(it->second) == INT_MAX - 1){
      ++it;
      continue;
    }
    PRINT_LOG(it->first << "\t\t\t" << ResolveNodeIpAddress((uint32_t)stoul(it->first)) << "\t\t"  
              << ReverseLookup(std::get<0>(it->second)) << "\t\t\t" << std::get<0>(it->second) << "\t\t" 
              << std::get<1>(m_neighborTable[ReverseLookup(std::get<0>(it->second))]) << "\t\t" 
              << std::to_string(std::get<1>(it->second)));
    
    checkRouteTableEntry(it->first, ResolveNodeIpAddress((uint32_t)stoul(it->first)), stoul(ReverseLookup(std::get<0>(it->second))),
                          std::get<0>(it->second), std::get<1>(m_neighborTable[ReverseLookup(std::get<0>(it->second))]),
                          std::get<1>(it->second));
    // for (Ipv4Address neighbor : std::get<1>(it->second)){
    //   // checkNeighborTableEntry(stoi(it->first), std::get<0>(it->second), std::get<1>(it->second));
    //   PRINT_LOG("\t\t" << ReverseLookup(neighbor) << "\t\t" << neighbor);
    // }
    ++it;
  }


  /* NOTE: For purpose of autograding, you should invoke the following function for each
  routing table entry. The output format is indicated by parameter name and type.
  */
  //  checkNeighborTableEntry();
}
void LSRoutingProtocol::RecvLSMessage(Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
  LSMessage lsMessage;
  Ipv4PacketInfoTag interfaceInfo;
  if (!packet->RemovePacketTag(interfaceInfo))
  {
    NS_ABORT_MSG("No incoming interface on OLSR message, aborting.");
  }
  uint32_t incomingIf = interfaceInfo.GetRecvIf();

  if (!packet->RemoveHeader(lsMessage))
  {
    NS_ABORT_MSG("No incoming interface on LS message, aborting.");
  }

  Ipv4Address interface;
  uint32_t idx = 1;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin(); //tha psaksw na vrw poios mou esteile to msg
       iter != m_socketAddresses.end(); iter++)
  {
    if (idx == incomingIf)
    {
      interface = iter->second.GetLocal(); // find the incoming interface
      break;
    }
    idx++;
  }

  switch (lsMessage.GetMessageType()) //san if statement me polla cases (if, else if)
  {
  case LSMessage::PING_REQ:
    ProcessPingReq(lsMessage);
    break;
  case LSMessage::PING_RSP:
    ProcessPingRsp(lsMessage);
    break;
  case LSMessage::HELLO_REQ:
    ProcessHelloReq(lsMessage);
    break;
  case LSMessage::HELLO_RSP:
    ProcessHelloRsp(lsMessage, interface);
    break;
  case LSMessage::LS_FLOOD:
    ProcessLSFlood(lsMessage, interface);
    break;
  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
}

void LSRoutingProtocol::ProcessPingReq(LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetPingReq().destinationAddress))
  {
    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received PING_REQ, From Node: " << fromNode
                                                 << ", Message: " << lsMessage.GetPingReq().pingMessage);
    // Send Ping Response
    LSMessage lsResp = LSMessage(LSMessage::PING_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
    lsResp.SetPingRsp(lsMessage.GetOriginatorAddress(), lsMessage.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsResp);
    BroadcastPacket(packet);
  }
}

void LSRoutingProtocol::ProcessPingRsp(LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetPingRsp().destinationAddress))
  {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
    iter = m_pingTracker.find(lsMessage.GetSequenceNumber()); //Sending node maintains state (destination, timestamp) of every PING_REQ sent (m_pingTracker)
    if (iter != m_pingTracker.end())
    {
      std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
      TRAFFIC_LOG("Received PING_RSP, From Node: " << fromNode
                                                   << ", essage: " << lsMessage.GetPingRsp().pingMessage);
      m_pingTracker.erase(iter);
    }
    else
    {
      DEBUG_LOG("Received invalid PING_RSP!");
    }
  }
}

void LSRoutingProtocol::ProcessHelloReq(LSMessage lsMessage)
{
  // Check destination address
    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received HELLO_REQ, From Node: " << fromNode);
    // Send Hello Response
    LSMessage lsResp = LSMessage(LSMessage::HELLO_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
    lsResp.SetHelloRsp(lsMessage.GetOriginatorAddress());
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsResp);
    BroadcastPacket(packet);
}

void LSRoutingProtocol::ProcessHelloRsp(LSMessage lsMessage, Ipv4Address interfaceAddr)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetHelloRsp().destinationAddress))
  {    
    Ipv4Address neighborAddr = lsMessage.GetOriginatorAddress();
    std::string nodeNumber = ReverseLookup(neighborAddr);
    m_neighborTable[nodeNumber] = std::tuple<Ipv4Address, Ipv4Address>(neighborAddr, interfaceAddr);
    m_neighborLog[nodeNumber] = Simulator::Now();
    m_networkChange = true;
    TRAFFIC_LOG("Received HELLO_RSP, From Node: " << ReverseLookup(lsMessage.GetOriginatorAddress()) 
        << "\tIP Address: " << neighborAddr << "\tInterface Address: " << interfaceAddr);
  }
  else
  {
    DEBUG_LOG("Received invalid HELLO_RSP!");
  }
}

void LSRoutingProtocol::ProcessLSFlood(LSMessage lsMessage, Ipv4Address interfaceAddr)
{
  
  // Check destination address
  if (IsOwnAddress(lsMessage.GetLSFlood().destinationAddress) && !IsOwnAddress(lsMessage.GetLSFlood().sourceAddress)) 
  {
    Ipv4Address neighborAddr = lsMessage.GetOriginatorAddress();
    std::string nodeNumber = ReverseLookup(neighborAddr);
    std::string sourceNodeNumber = ReverseLookup(lsMessage.GetLSFlood().sourceAddress);

    TRAFFIC_LOG("Received LS_FLOOD, From Node: " << nodeNumber);

    // Check if this is a new entry
    bool newEntry = m_validLSP.find(sourceNodeNumber) == m_validLSP.end() 
      || std::get<0>(m_validLSP[sourceNodeNumber]) < lsMessage.GetSequenceNumber();

    if (newEntry){
      // Fill out corresponding m_validLSP entry 
      m_validLSP[sourceNodeNumber] = 
        std::tuple<uint64_t, std::vector<Ipv4Address>>(lsMessage.GetSequenceNumber(), std::vector<Ipv4Address>());
      for (Ipv4Address &neighbour : lsMessage.GetLSFlood().neighbours){
        std::get<1>(m_validLSP[ReverseLookup(lsMessage.GetLSFlood().sourceAddress)]).push_back(neighbour);
      }
      if (lsMessage.GetTTL() > 0){
        Flood(lsMessage);
      }
    }
  } 
  else 
  {
    DEBUG_LOG("Received invalid LS_FLOOD!");
  }
}

bool LSRoutingProtocol::IsOwnAddress(Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ipv4InterfaceAddress interfaceAddr = i->second;
    if (originatorAddress == interfaceAddr.GetLocal())
    {
      return true;
    }
  }
  return false;
}

void LSRoutingProtocol::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    Ptr<PingRequest> pingRequest = iter->second;
    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage()
                                          << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds()
                                          << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      // Remove stale entries
      m_pingTracker.erase(iter++);
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

void LSRoutingProtocol::SayHello()
{
  // DEBUG_LOG("Saying Hello...");
  uint32_t sequenceNumber = GetNextSequenceNumber();
  TRAFFIC_LOG("Broadcasting HELLO_REQ" << " SequenceNumber: " << sequenceNumber);
  Ptr<Packet> packet = Create<Packet>();
  LSMessage lsMessage = LSMessage(LSMessage::HELLO_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
  packet->AddHeader(lsMessage);
  BroadcastPacket(packet);

  std::map<std::string, Time>::iterator it = m_neighborLog.begin();
  std::vector<std::string> deleteList;
  while (it != m_neighborLog.end()) {
    if (it->second + m_helloTimeout < Simulator::Now()){
      m_networkChange = true;
      deleteList.push_back(it->first);
    }
    ++it;
  }

  for (std::string node : deleteList) {
    m_neighborTable.erase(node);
    m_neighborLog.erase(node);
  }

  m_helloTimer.Schedule(m_helloTimeout);
}

void LSRoutingProtocol::Flood(LSMessage lsMessage) 
{
  // TODO: Deal with TTL == 0
  // Looping over neighbors and sending the packet
  for (auto const& entry : m_neighborTable) {
    if (ReverseLookup(lsMessage.GetOriginatorAddress()) == ReverseLookup(std::get<0>(entry.second))){
      continue;
    }
    LSMessage lsFlood = LSMessage(LSMessage::LS_FLOOD, lsMessage.GetSequenceNumber(), lsMessage.GetTTL() - 1, m_mainAddress);
    Ipv4Address neighborAddr = std::get<0>(entry.second);

    lsFlood.SetLSFlood(neighborAddr, lsMessage.GetLSFlood().sourceAddress, lsMessage.GetLSFlood().neighbours);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsFlood);
    BroadcastPacket(packet);
  }
}

void LSRoutingProtocol::LSAdvertise()
{
  if (!m_networkChange) {
    m_lsTimer.Schedule(m_lsTimeout);
    return;
  }

  // STATUS_LOG("Network Changed!")

  std::vector<Ipv4Address> neighbors;
  for (auto const& entry : m_neighborTable) {
    neighbors.push_back(std::get<0>(entry.second));
  }
  for (auto const& entry : m_neighborTable) {

    LSMessage lsFlood = LSMessage(LSMessage::LS_FLOOD, GetNextSequenceNumber(), m_maxTTL, m_mainAddress);
    Ipv4Address neighborAddr = std::get<0>(entry.second);
    lsFlood.SetLSFlood(neighborAddr, m_mainAddress, neighbors);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsFlood);
    BroadcastPacket(packet);
  }

  RecalculateNetwork();

  m_lsTimer.Schedule(m_lsTimeout);
}

bool sortbysec(const std::pair<std::string, int>& a,  
               const std::pair<std::string, int>& b) 
{ 
    return (a.second < b.second); 
} 

std::string printConfirmed(std::map<std::string, std::tuple<int, std::string>> inputmap) {
  std::string returnstring = "";
  for (auto &entry : inputmap) {
    returnstring += entry.first + ", " + std::to_string(std::get<0>(entry.second)) + ", " + std::get<1>(entry.second) + ", " + "\n";
  }
  return returnstring;
}

std::string printMap(std::map<std::string, int> inputmap) {
  std::string returnstring = "";
  for (auto &entry : inputmap) {
    returnstring += entry.first + ": " + std::to_string(entry.second) + "\n";
  }
  return returnstring;
}

std::string printMap(std::map<std::string, std::string> inputmap) {
  std::string returnstring = "";
  for (auto &entry : inputmap) {
    returnstring += entry.first + ": " + entry.second + "\n";
  }
  return returnstring;
}

void LSRoutingProtocol::RecalculateNetwork() 
{
  using namespace std;

  // std::map<std::string, std::tuple<uint64_t, std::vector<Ipv4Address>>>::iterator it = m_validLSP.begin();

  // STATUS_LOG("LSP TABLE");
  // while (it != m_validLSP.end())
  // {
  //   PRINT_LOG("Node " << it->first << "\t\t" << "Sequence " << std::get<0>(it->second));
  //   // for (Ipv4Address neighbor : std::get<1>(it->second)){
  //   //   // checkNeighborTableEntry(stoi(it->first), std::get<0>(it->second), std::get<1>(it->second));
  //   //   PRINT_LOG("\t\t" << ReverseLookup(neighbor) << "\t\t" << neighbor);
  //   // }
  //   ++it;
  // }

  map<string, int> costs;
  map<string, string> parents;

  map<string, tuple<int, string>> confirmed;
  unordered_set<string> visited;
  vector<tuple<string, int, string>> tentative;

  for (auto &entry : m_validLSP) {
    costs[entry.first] = INT_MAX - 1;
  }

  costs[ReverseLookup(m_mainAddress)] = 0;
  parents[ReverseLookup(m_mainAddress)] = "";

  for (auto &entry : m_neighborTable) {
    costs[entry.first] = 1;
    parents[entry.first] = ReverseLookup(m_mainAddress);
  }

  // STATUS_LOG(printMap(costs));

  while (confirmed.size() < m_validLSP.size() + 1)
  {
    auto entry = min_element(costs.begin(), costs.end(), sortbysec);
    // STATUS_LOG("m_validLSP: " << to_string(m_validLSP.size()) << "\t\t confirmed: " << to_string(confirmed.size()));
    // STATUS_LOG("Adding " << entry->first);
    if (costs.size() == 0){
    }
    string nodeNumber = entry->first;
    int cost = entry->second;
    string parent = parents[nodeNumber];
    if (visited.count(nodeNumber) == 0) 
    {
      confirmed[nodeNumber] = tuple<int, string>(cost, parent);
      visited.insert(nodeNumber);
      if (m_validLSP.find(nodeNumber) != m_validLSP.end())
      {
        for (auto &neighbor : get<1>(m_validLSP[nodeNumber])) 
        {
          if (visited.count(ReverseLookup(neighbor)) == 0)
          {
            if (cost + 1 < costs[ReverseLookup(neighbor)] || costs.find(ReverseLookup(neighbor)) == costs.end())
            {
              costs[ReverseLookup(neighbor)] = cost + 1;
              parents[ReverseLookup(neighbor)] = nodeNumber;
            }
          }
        }
      }
      costs.erase(nodeNumber);
      parents.erase(nodeNumber);
    }
  }
  map<string, string> nextHop;
  for (auto &entry : confirmed){
    string curr = get<1>(entry.second);
    if (entry.first == ReverseLookup(m_mainAddress)){
      continue;
    } else if (curr == ReverseLookup(m_mainAddress)){
      nextHop[entry.first] = entry.first;
      continue;
    }
    while (m_neighborTable.find(curr) == m_neighborTable.end() && curr != ""){
      curr = get<1>(confirmed[curr]);
    }
    nextHop[entry.first] = curr;

  }

  m_routingTable.clear();

  for (auto &entry : confirmed) {
    if (entry.first == ReverseLookup(m_mainAddress)){
      continue;
    }
    uint32_t nodeNumber = nextHop[entry.first].size() > 0 ? stoul(nextHop[entry.first]) : 20000;
    m_routingTable[entry.first] = tuple<Ipv4Address, int>(ResolveNodeIpAddress(nodeNumber), std::get<0>(entry.second));
  }
  
  m_networkChange = false;
}

uint32_t
LSRoutingProtocol::GetNextSequenceNumber()
{
  m_currentSequenceNumber = (m_currentSequenceNumber + 1) % (LS_MAX_SEQUENCE_NUMBER + 1);
  return m_currentSequenceNumber;
}

void LSRoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp(i);
}
void LSRoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown(i);
}
void LSRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress(interface, address);
}
void LSRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress(interface, address);
}

void LSRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
  NS_ASSERT(ipv4 != 0);
  NS_ASSERT(m_ipv4 == 0);
  NS_LOG_DEBUG("Created ls::RoutingProtocol");
  // Configure timers
  m_auditPingsTimer.SetFunction(&LSRoutingProtocol::AuditPings, this);
  m_helloTimer.SetFunction(&LSRoutingProtocol::SayHello, this);
  m_lsTimer.SetFunction(&LSRoutingProtocol::LSAdvertise, this);
  
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4(m_ipv4);
}