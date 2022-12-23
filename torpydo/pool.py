# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - Nodes
# Description: Torpydo Pool index server
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ====
# Asynchronous tasking and networking
import asyncio

# Enum
from enum import Enum

# Time lib
import time


# === Enums ===
class PoolIndexLogType(Enum):
    INFO = 0
    STATUS = 1
    ERROR = 2

# === Classes ===
class NodeInfo:
    def __init__(self, host: str, port: int) -> None:
        """
        Torpydo Node Info.

        Arguments:
        host -- Listening address of the node.
        port -- Listening TCP port of the node.
        """

        # (public) Listening address of the node.
        self.host = host
        # (public) Listening TCP port of the node.
        self.port = port

        # (public) Time on which the node entry is deprecated (node considarated
        # as dead).
        self.deprecation = None

    def set_deprecation(self, delay: float=60.0):
        """
        Set a delay before node info deprecation.

        Arguments:
        delay -- Delay (in s) before the node info become deprecated (default 60.0).
        """
        self.deprecation = time.time() + delay

class PoolIndex:
    def __init__(self, host: str, port: int) -> None:
        """
        Torpydo Pool index server.

        Arguments:
        host -- Address on which the pool index server shoud listen for connection.
        port -- TCP port on which the pool index server listen for connection.
        """

        # (private) Listening address
        self._host = host
        # (private) Listening TCP port
        self._port = port

        # (private) Asyncio server instance
        self._server = None

        # (private) Nodes info dict
        self._nodes_infos = {}

        # (private) Bufferized nodes info array
        self._nodes_infos_buffer = b""

        # (private) Requested delay (in s) between heartbeat
        self._requested_delay = 15
        # (private) Deprecation delay (in s)
        self._deprecation_delay = 30.0
        # (private) Garbage collector cycle (in s)
        self._garbage_collector_cycle = 10.0

        # (private) Logging flag
        self._logging = False

    
    # -- Public methods --
    async def start(self) -> None:
        """
        Creates a TCP socket to listen for connections. And starts a garbage
        collector task to remove deprecated node info entries.
        """
        self._server = await asyncio.start_server(self._handle_connection, self._host, self._port)
        self._log(PoolIndexLogType.STATUS, f"Pool index server is listening on {self._host}:{self._port}.")

        await asyncio.gather(self._server.serve_forever(), self._depracated_info_garbage_collector())

    
    def set_log(self, flag: bool) -> None:
        """
        Set whenever the pool index server should log information to console.

        Arguments:
        flag -- Logging toggle.
        """
        self._logging = flag


    def set_requested_delay(self, delay: int) -> None:
        """
        Set requested delay.

        Arguments:
        delay -- Delay (in s)
        """
        self._requested_delay = delay
    

    def set_deprecation_delay(self, delay: float) -> None:
        """
        Set deprecation delay.

        Arguments:
        delay -- Delay (in s).
        """
        self._deprecation_delay = delay
    

    def set_garbage_collector_cycle(self, cycle: float) -> None:
        """
        Set node info garbage collector cycle.

        Arguments:
        cycle -- Cycle (in s).
        """
        self._garbage_collector_cycle = cycle


    # -- Private methods --
    def _bufferize_nodes_info(self) -> None:
        """
        Compiles nodes info data to a sendable buffer.
        """
        buffer = b""
        for _, node in self._nodes_infos.items():
            buffer += node.host.encode() + b"\x00" + node.port.to_bytes(2)
        
        self._nodes_infos_buffer = buffer
    

    async def _depracated_info_garbage_collector(self) -> None:
        """
        Removes deprecated nodes info every cycle time.
        Updates nodes infos buffer at each cycle.
        """
        while True:
            keys_to_remove = []
            current_time = time.time()
            for key, node_info in self._nodes_infos.items():
                if current_time > node_info.deprecation:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                removed = self._nodes_infos.pop(key)
                self._log(PoolIndexLogType.INFO, f"Removed node {removed.host}:{removed.port}.")
            
            self._bufferize_nodes_info()
            await asyncio.sleep(self._garbage_collector_cycle)
    

    async def _handle_connection(self, peer_reader: asyncio.StreamReader, peer_writer: asyncio.StreamWriter) -> None:
        """
        Handles a peer connection to the pool index server.

        Arguments:
        peer_reader -- Stream reader of the peer TCP socket.
        peer_writer -- Stream writer of the peer TCP socket.
        """
        try:
            command = await peer_reader.readexactly(1)
        except:
            self._log(PoolIndexLogType.ERROR, "Peer closed connection.")
        
        if command == b"\x00": # Get node list
            peer_writer.write(self._nodes_infos_buffer)
            await peer_writer.drain()

            host, port = peer_writer.get_extra_info("peername")
            self._log(PoolIndexLogType.INFO, f"Sent node list to {host}:{port}.")
        elif command == b"\01": # Heartbeat
            try:
                host_bytes = await peer_reader.readuntil(b"\x00")
                port_bytes = await peer_reader.readexactly(2)
            except:
                self._log(PoolIndexLogType.ERROR, "Peer closed connection.")
            
            host = host_bytes[:-1].decode()
            port = int.from_bytes(port_bytes)
            node_info = self._nodes_infos.get(f"{host}:{port}")
            
            if not node_info:
                node_info = NodeInfo(host, port)
                self._nodes_infos[f"{host}:{port}"] = node_info
                self._log(PoolIndexLogType.INFO, f"Added node {host}:{port}")
                self._bufferize_nodes_info()

            node_info.set_deprecation(self._deprecation_delay)
            
            peer_writer.write(self._requested_delay.to_bytes(1))
            await peer_writer.drain()
        
        peer_writer.close()
        await peer_writer.wait_closed()
    

    def _log(self, type: PoolIndexLogType, message: str) -> None:
        """
        Log a message to the console if logging flag is set.

        Arguments:
        type    -- Type of log.
        message -- Message to log.
        """
        if self._logging:
            print(f"[Torpydo Pool Index]<{type.name}> - {message}")
