# TorPydo Basic Node setup

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