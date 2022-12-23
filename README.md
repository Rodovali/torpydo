🧅 torpydo 🚀
=============

📜 TOR-like stream-based networking system in Python.

💻 Made with ❤️ by Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidin MAHMALJI and Bao HAN.

## 📄 Description
This project was created as part of the *Networks and Protocols* first-year MSc
in Electrical Engineering course given at the **Brussels Faculty of Engineering**.

Torpydo is a stream based peer-to-peer decentralized onion routing platform 
written in Python. Its goal is to anonymize end-to-end TCP connections, relying 
on multiple encryptions of the TCP stream segments (like an onion) and on a 
particular peer-to-peer architecture where nodes do not know anything about the
nature of their source and destination and about the data segments they are 
forwarding.

Anonymity is further guaranteed thanks to the stream ciphers used, 
rendering nodes unable to know their role in the chain (no un-padding).

## 💾 Installation, Update and Removal

To install `torpydo` the easiest way is to use `pip`:
- Download the repository and go to the cloned directory
```
$ git clone https://github.com/Rodovali/torpydo.git
$ cd torpydo
```
- Build and install the library
```
$ pip install .
```

To update the library: 
- Go to the cloned git directory, and pull any change:
```
$ git pull
```
- Rebuild and update the library
```
$ pip install --upgrade .
```

To remove the library:
```
$ pip uninstall torpydo
```

## ⚡ Quick start
This section gives examples of minimal code to use the three torpydo entities.

You can also directly execute the example codes in the `examples` directory,
in which there are pre-configured pool index and node in addition to a simple
http proxy redirecting http requests to their recipient server through a torpydo
network. 

For more details, feel free to consult the documentation section below.

### Using the torpydo client lib
```py
# Torpydo basic client lib usage example

# === Libraries ===
import asyncio
from torpydo.client import Client

# === Main function ===
async def main():
    client = Client() # Instenciate a new torpydo client
    await client.sync_nodes_list("127.0.3.2", 8080) # Get index pool known nodes adresses
    await client.random_path_to_destination("127.0.0.1", 8080, 3) # Construct a random path of 3 nodes to destination
    await client.send(b"Hello") # Send data to the destination
    data = await client.receive(32) # Await receiving data from the destination
    print(data) # Print data

# === Main code ===
if __name__ == "__main__":
    asyncio.run(main())

```


### Hosting a torpydo node

```py
# Torpydo Basic Node setup

# === Libraries ===
import asyncio
from torpydo.node import Node

# === Config ===
HOST = "127.0.2.3" # Address on which the node will listen
PORT = 6000        # TCP port on which the node will listen

POOL_INDEX_HOST = "127.0.3.2" # Address of a pool index server to notify
POOL_INDEX_PORT = 8080 # TCP Port of a pool index server to notify

# === Main code ===
if __name__ == "__main__":
    node = Node(HOST, PORT) # Instenciate a new torpydo node
    node.set_pool_index(POOL_INDEX_HOST, POOL_INDEX_PORT) # Set node's pool index server (optional)
    node.set_log(True) # Activate logging infos to console (optional)
    asyncio.run(node.start()) # Start the node

```


### Hosting a torpydo pool index

```py
# Torpydo Basic Pool Index Server setup

# === Libraries ===
import asyncio
from torpydo.pool import PoolIndex

# === Config ===
HOST = "127.0.3.2" # Address on which the pool index server will listen.
PORT = 8080        # TCP port on which the pool index server will listen.

# === Main Code ===
if __name__ == "__main__":
    pool_index = PoolIndex(HOST, PORT) # Instenciate a new pool index server.
    pool_index.set_log(True) # Activate logging infos to console (optional).
    asyncio.run(pool_index.start()) # Start the pool index server.

```

## 📚 Documentation

### TPDP
The TorPyDo Protocol 0.1 is fully documented in the file `TPDP.md`

### Node
A node is the base building block of a torpydo network. It routes, encrypts, and
decrypts data segments through the network, toward their destinations.

#### Constructor
```py
Node(host: str, port: int) -> Node
```
Creates a new torpydo node instance whose hostname is `host` and TCP port is `port`.

#### Methods
```py
async start() -> None
```
Starts listening for connections. Should be runned in a asyncio event loop.

```py
set_pool_index(host: str, port: int) -> None
```
Sets the hostname and the port of the pool index server. This server is the one notified about the existence of this new node.

```py
set_log(flag: bool) -> None
```
Enables or disables the logging to console depending on the value of `flag`

### Client
A client is the entity who wants to communicate anonymously with a destination
peer through the toprydo network. 

#### Constructor
```py
Client() -> Client
```
Creates a new client instance

#### Methods
```py
async connect(host: str, port: int) -> None
```
Connects the client to the first node with hostname `host` at port `port`.

```py
async next_destination(host: str, port: int) -> None
```
Performs a handshake with the node whose hostname is `host` at port `port`, making that node the new final node of the path.

```py
async random_path_to_destination(host: str, port: int, n: int) -> None
```
Creates a path to the node with hostname `host` at port `port` by picking `n` random nodes from the list of known nodes.

```py
async sync_nodes_list(host: str, port: int) -> None
```
Receives the list of nodes known by the server with hostname `host` at port `port` and updates its own list of known nodes by adding previously unknown ones.

```py
async purge_nodes_list() -> None
```
Clears the list of known nodes.

```py
async send(data: bytes) -> None
```
Sends data to the last destination.

```py
async close() -> None
```
Close TCP connection with first node, breaking all the chain.

```py
async receive(buffer_size: int) -> bytes
```
Waits for data from the last destination. `buffer_size` sets the maximal size of the received data.

```py
async receive_exactly(n: int) -> bytes
```
Receive exactly `n` bytes from destination.


### Pool Index
A pool index is a server who maintains a list of known nodes for a client to
chose from. The nodes in the pool should contact their pool index server regularly
to be considered alive by the pool index.

#### Constructor
```py
PoolIndex(host: str, port: int) -> PoolIndex
```
Creates a pool index server instance.

#### Methods
```py
async start() -> None
```
Starts listening for connections. Should be runned in a asyncio event loop.

```py
set_log() -> None
```
Enables or disables the logging to console depending on the value of `flag`

```py
set_requested_delay() -> None
```
Sets the delay (in s) that will be send to nodes for their next heartbeat

```py
set_deprecation_delay(delay: float) -> None
```
Sets the deprecation delay (in s) after which to remove a node from the list if no heartbeat was received from a node.

```py
set_garbage_collector_cycle(cycle: float) -> None
```
Sets the delay between each node info gargabe collector cycle (in s).
