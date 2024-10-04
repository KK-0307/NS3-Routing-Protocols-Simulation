
# NS3-Routing-Protocols-Simulation
Program designed to simulate Distance Vector (DV) and Link State (LS) routing protocols, along with implementations of Chord and PennSearch. The program simulates various network topologies and routing scenarios, allowing for detailed analysis of the performance of different protocols.

Please note that **this code should not be copied or reused**, as it is part of a group project and may contain proprietary work from all team members. Reuse or replication of the code may violate academic integrity guidelines.

## Routing Protocols Overview

### Distance Vector Routing Protocol (DV)
The **DV routing protocol** is implemented under the `dv-routing-protocol` folder. DV is a distributed routing protocol where each node shares its routing table with its immediate neighbors. Nodes iteratively update their tables based on information received from neighbors, eventually converging to the shortest path to all destinations.

- **How it works**: 
  - Each node keeps a distance vector, which stores the shortest known distance to each destination in the network.
  - Nodes periodically exchange vectors with their neighbors.
  - Upon receiving a vector, a node updates its own table based on the newly received information.
  - The goal is to propagate knowledge of the shortest paths throughout the network.

### Link State Routing Protocol (LS)
The **LS routing protocol** is implemented under the `ls-routing-protocol` folder. LS is a more centralized protocol where each node gathers full information about the entire network topology and computes the shortest paths using Dijkstra’s algorithm.

- **How it works**:
  - Each node broadcasts its local connectivity (i.e., its direct neighbors and link costs) to every other node in the network.
  - Every node then has a full map of the network topology.
  - Using this map, each node runs Dijkstra’s algorithm to calculate the shortest path to each destination.

### Chord Distributed Hash Table (DHT)
The **Chord** algorithm is a distributed lookup protocol for peer-to-peer systems. It efficiently locates the node responsible for storing a particular piece of data using consistent hashing.

- **How it works**:
  - Nodes are arranged in a ring structure, and each node is assigned a unique ID.
  - Each node maintains information about its immediate neighbors and a small subset of distant nodes (called fingers) to ensure efficient lookups.
  - Data is mapped to nodes based on their IDs, and the lookup process is logarithmic in the number of nodes.

### PennSearch 
**PennSearch** builds on top of Chord, introducing custom search functionality to improve data retrieval across distributed systems.

- **How it works**:
  - PennSearch optimizes search queries by minimizing the number of lookups required and ensuring data availability across multiple nodes.
  - The implementation includes hashing, search indexing, and fault tolerance mechanisms.

### Compiling

1. If running the simulator for the first time, configure the build system:
```bash
   ./waf configure
```
2. If the `waf` executable lacks execution permission, run:
```bash
chmod u+x waf
```
3. Compile the simulator using:
```bash
./waf 
```
4. Run the simulator using:
```bash
./waf --run "simulator-main --routing=<NS3/LS/DV> --scenario=./scratch/scenarios/<SCENARIO_FILE_NAME>.sce --inet-topo=./scratch/topologies/<TOPOLOGY_FILE_NAME>.topo --project=<1/2>"
```

### Troubleshooting
If you encounter compilation errors, clear the build cache using:
```bash
./waf distclean
``` 