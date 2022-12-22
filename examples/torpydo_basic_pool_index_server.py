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

