# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - Client
# Description: Client Class for Torpydo
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
# Asynchronous tasking and networking
import asyncio

# TPDP Client
from torpydo.tpdp import TPDPClient

# Cryptographically strong randomness
from secrets import SystemRandom


# === Classes ===  
# - Client -
class Client():
    def __init__(self) -> None:
        self._tpdp_handler = None
        self._node_infos = {}


    async def connect(self, host: str, port: int) -> None:
        """
        Opens a connection to the first node and instantiates a TPDP handler.

        Arguments:
        host -- Hostname of the node destination.
        port -- TCP Port of the node destination.
        """
        node_reader, node_writer = await asyncio.open_connection(host, port)
        self._tpdp_handler = TPDPClient(node_reader, node_writer)


    async def next_destination(self, host: str, port: int) -> None:
        """
        Performs a handshake with the next node through the previous one/ones.

        Arguments:
        host -- Hostname of the node destination.
        port -- TCP Port of the node destination.
        """
        await self._tpdp_handler.next_handshake(host, port)


    async def send(self, data: bytes) -> None:
        """
        Sends data to the final node added through the previous nodes.

        Arguments:
        data -- Data to send.
        """
        await self._tpdp_handler.send(data)
        

    async def receive(self, buffer_size: int) -> bytes:
        """
        Awaits for data from the final node.
        
        Arguments:
        buffer_size -- Max bytes to receive.
        
        Returns:
        Received decrypted data
        """
        return await self._tpdp_handler.receive(buffer_size)
    

    async def random_path_to_destination(self, host: str, port: int, n: int) -> None:
        """
        Creates a path to the destination by picking random nodes from a
        list of known nodes.

        Arguments:
        host -- Hostname of the node destination.
        port -- TCP Port of the node destination.
        n    -- Number of nodes in the path.
        """
        if len(self._node_infos) < n:
            raise Exception("Not enough known nodes to create a path of desired length.")
        
        nodes = list(self._node_infos.values())
        random_generator = SystemRandom()

        first_node = nodes.pop(random_generator.randint(0,len(nodes)-1))
        await self.connect(first_node[0], first_node[1])

        for i in range(n-1):
            next_node = nodes.pop(random_generator.randint(0, len(nodes)-1))
            await self.next_destination(next_node[0], next_node[1])
         
        await self.next_destination(host, port)


    async def sync_nodes_list(self, host: str, port: int) -> None:
        """
        Synchronizes the list of nodes with a pool index server.

        Arguments:
        host -- Hostname of the pool index server.
        port -- TCP Port of the pool index server.
        """
        reader, writer = await asyncio.open_connection(host, port)
        
        writer.write(b"\x00")
        await writer.drain()
        
        while True:
            flag = await self._receive_node_info(reader)
            if not flag:
                break
        
        writer.close()
        await writer.wait_closed()

        
    async def purge_nodes_list(self) -> None:
        """
        Purges the list of nodes.
        """
        self._nodes_infos = {}
    

    async def _receive_node_info(self, reader: asyncio.StreamReader) -> bool:
        """
        Reads one node info pair from TCP stream.

        Arguments:
        reader -- Stream reader of the pool index TCP stream.

        Returns:
        Whether the stream has reached EOF or not.
        """
        try:
            node_host_bytes = await reader.readuntil(b"\x00")
        except asyncio.IncompleteReadError:
            return False
        
        node_host = node_host_bytes[:-1].decode()
        
        node_port_bytes = await reader.readexactly(2)
        node_port = int.from_bytes(node_port_bytes)

        if not self._node_infos.get(f"{node_host}:{node_port}"):
            self._node_infos[f"{node_host}:{node_port}"] = (node_host, node_port)
        
        return True
