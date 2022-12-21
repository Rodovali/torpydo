# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - Nodes
# Description: Torpydo Node
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
# Asynchronous tasking and networking
import asyncio

# Enums
from enum import Enum

# TPDP handler
from tpdp import TPDPService


# === Enums ===
class NodeLogType(Enum):
    INFO = 0
    STATUS = 1
    ERROR = 2


# === Classes ===
class Node:
    def __init__(self, host: str, port: int) -> None:
        """
        Torpydo Node.

        Arguments:
        host -- Address on which the node should listen for connection.
        port -- TCP port on which the node should listen for connection.
        """
        # (private) Listening address
        self._host = host
        # (private) Listening TCP port
        self._port = port

        # (private) Asyncio server instance
        self._server = None

        # (private) Pool index server address
        self._pool_index_host = None
        # (private) Pool index server port
        self._pool_index_port = None

        # (private) Loging flag
        self._loging = False


    # -- Public methods --    
    async def start(self) -> None:
        """
        Creates a TCP socket to listen for connections and starts a heartbeat
        task to notify a pool index server of the node existence.
        """
        self._server = await asyncio.start_server(self._handle_connection, self._host, self._port)
        self._log(NodeLogType.STATUS, f"Node is listening on {self._host}:{self._port}.")
        
        
        await asyncio.gather(self._server.serve_forever(), self._send_heartbeats())


    def set_pool_index(self, host: str, port: int) -> None:
        """
        Set up node pool index server address and port.

        Arguments:
        host -- Pool index server address.
        port -- Pool index server TCP port.
        """
        self._pool_index_host = host
        self._pool_index_port = port


    def set_log(self, flag: bool) -> None:
        """
        Set whenever the node should log information to the console.

        Arguments:
        flag -- Loging toggle.
        """
        self._loging = flag


    # -- Private methods --
    def _log(self, type: NodeLogType, message: str) -> None:
        """
        Log a message to the console if loging flag is set.

        Arguments:
        type    -- Type of log.
        message -- Message to log.
        """
        if self._loging:
            print(f"[Torpydo Node]<{type.name}> - {message}")


    async def _handle_connection(self, source_reader: asyncio.StreamReader, source_writer: asyncio.StreamWriter) -> None:
        """
        Handles a peer connection to the node. Creates a TPDP service instance,
        try to handshake with the peer and begin to forward data if successful.
        Otherwise closes the connection with the peer.

        Arguments:
        source_reader -- Stream reader of the peer TCP socket.
        source_writer -- Stream writer of the peer TCP socket.
        """
        # Create an instance of TPDP service
        tpdp_handler = TPDPService(source_reader, source_writer)
        
        # Activate loging depending on loging flag of the node
        tpdp_handler.set_log(self._loging)

        host, port = source_writer.get_extra_info("peername")
        self._log(NodeLogType.INFO, f"New connection from {host}:{port}.")

        # Try a handshake with the peer
        handshake_succeeded = await tpdp_handler.handshake(timeout=10.0)

        # If successful begin to forward data
        if handshake_succeeded:
            await tpdp_handler.route()
            return
        
        # Otherwises closes the connection with the peer.
        source_writer.close()
        await source_writer.wait_closed()


    async def _send_heartbeats(self, default_delay: float=10.0) -> None:
        """
        Tries to send a heartbeat to a pool index server. If successful,
        schedule next heartbeat depending on server information. Otherwise
        reschedule a heart beat after default_delay.
        
        Arguments:
        default_delay -- Delay of the next heartbeat if connection with the pool
                         index server was unsuccessful (default 10.0).
        """
        while True:
            # Don't try to connect if pool index server information is not set
            if not self._pool_index_host or not self._pool_index_port:
                await asyncio.sleep(default_delay)
                continue

            # Try to connect to pool index server
            reader, writer, delay = None, None, None
            try:
                reader, writer = await asyncio.open_connection(self._pool_index_host, self._pool_index_port)
            except:
                self._log(NodeLogType.ERROR, f"Can't connect to pool index server, next try in {default_delay}s.")

            # If successfull send node infos (listening address and TCP port)
            if writer:
                writer.write(b"\x01") # Node heartbeat command.
                writer.write(self._host.encode())
                writer.write(b"\x00")
                writer.write(self._port.to_bytes(2))
                await writer.drain()

                # Await pool index server wanted delay before next heartbeat
                try:
                    delay = await reader.readexactly(1)
                    delay = float(delay[0])
                    self._log(NodeLogType.INFO, f"Heartbeat sent, next heartbeat in {delay}s.")
                except:
                    self._log(NodeLogType.ERROR, "Pool index server closed the connection.")
                
                writer.close()
                await writer.wait_closed()

            # Schedule another heartbeat
            await asyncio.sleep(delay or default_delay)
