# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - TPDP interface
# Description: TorPyDo Protocol (TPDP) classes
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
# Asynchronous tasking and networking
import asyncio

# Enumerations
from enum import Enum

# Cryptographically strong randomness generation
from secrets import token_bytes
# Elliptic curve Diffie-Hellman key exchange algorithm
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
# Key serialization config enums
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# HMAC-based Extract-and-Expand Key Derivation Function
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# 256 bits Advanced Encryption Standard with Counter mode
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CTR


# === Enums ===
class TPDPError(Enum):
    TIMEOUT_ERROR = 0
    PROTOCOL_ERROR = 1
    DESTINATION_CONNECTION_ERROR = 2

class TPDPLogType(Enum):
    INFO = 0
    STATUS = 1
    ERROR = 2


# === Classes ===
class TPDPService:
    def __init__(self, source_reader: asyncio.StreamReader, source_writer: asyncio.StreamWriter) -> None:
        """
        TorPyDo Protocol (TPDP) handling class for serving peers (nodes).

        Arguments:
        source_reader -- Socket stream reader of the source TCP connection.
        source_writer -- Socket stream writer of the source TCP connection.
        """
        # (public) Protocol version
        self.version = "0.1"

        # (private) Socket stream reader/writer of the source TCP connection.
        self._source_reader = source_reader
        self._source_writer = source_writer

        # (private) Socket stream reader/writer of the destination TCP connection.
        self._destination_reader = None
        self._destination_writer = None

        # (private) AES256-CTR Cipher, Encryptor and Decryptor
        self._cipher = None
        self._encryptor = None
        self._decryptor = None

        # (private) Handshake flag
        self._handshaked = False

        # (private) Log flag
        self._logging = False

        # (private) Connection closed flag
        self._closed = False


    # -- Public methods --
    async def handshake(self, timeout: float = 10.0) -> bool:
        """
        Await for a client hello and proceed with a TPDP/0.1 handshake:
            <- Await source peer Hello
            -> Send node Hello to source peer
            -- Generate node X25519 private key
            <- Await source peer X25519 public key
            -> Send node X25519 public key to peer
            -- Calculate X25519 shared key and derive a useable key via HKDF
            <- Await source peer randomly generated nonce for AES256/CTR cipher
            -- Create AES256/CTR cipher instance
            -> Send OK (ACK) to peer
            <- Await source peer desired destination encrypted hostname length
            <- Await source peer desired destination encrypted hostname
            -> Send OK (ACK) to peer
            <- Await source peer desired destination encrypted port
            -- Connect to destination
            -> Send Handshake OK (ETB) or error code to peer
        
        Arguments:
        timeout -- Time (in s) the server will await at each step before cutting
                   the connection with the client (default 10.0).

        Returns:
        Handshake success. 
        """
        # <- Await source peer Hello
        hello_data = await self._receive_from_source_timeout(16, timeout)

        if not hello_data:
            return False
        elif hello_data != b"Hello TPDP/0.1\r\n":
            await self._write_error_to_source(TPDPError.PROTOCOL_ERROR)
            return False
        
        self._log(TPDPLogType.STATUS, "Handshake start.")

        # -> Send node Hello to peer
        await self._write_to_source(b"Hello TPDP/0.1\r\n")

        # -- Generate node X25519 private key
        private_key = X25519PrivateKey.generate()

        self._log(TPDPLogType.STATUS, "Private key generated.")

        # <- Await source peer X25519 public key
        peer_public_key_bytes = await self._receive_from_source_timeout(32, timeout)
        
        if not peer_public_key_bytes:
            return False
        
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

        self._log(TPDPLogType.STATUS, f"Received source public key: {peer_public_key_bytes}.")

        # -> Send node X25519 public key to peer
        await self._write_to_source(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

        # -- Calculate X25519 shared key and derive a useable key via HKDF
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"TPDP/0.1").derive(shared_key)

        self._log(TPDPLogType.STATUS, "Key exchange complete.")

        # <- Await source peer randomly generated nonce for AES256/CTR cipher
        ctr_nonce = await self._receive_from_source_timeout(16, timeout)

        if not ctr_nonce:
            return False
        
        self._log(TPDPLogType.STATUS, f"Received encryption nonce: {ctr_nonce}.")

        # -- Create AES256/CTR cipher instance
        self._cipher = Cipher(AES256(derived_key), CTR(ctr_nonce))
        self._encryptor = self._cipher.encryptor()
        self._decryptor = self._cipher.decryptor()

        self._log(TPDPLogType.STATUS, "Cipher configured.")

        # -> Send node ACK to peer
        await self._write_to_source(b"\x06\x06")

        # <- Await source peer desired destination encrypted hostname length
        host_length_raw = await self._receive_from_source_timeout(2, timeout)

        if not host_length_raw:
            return False

        host_length = int.from_bytes(host_length_raw)

        # <- Await source peer desired destination encrypted hostname
        host_encrypted_bytes = await self._receive_from_source_timeout(host_length, timeout)

        if not host_encrypted_bytes:
            return False
        
        host_bytes = self._decryptor.update(host_encrypted_bytes)
        host = host_bytes.decode()

        self._log(TPDPLogType.STATUS, f"Received destination hostname: {host}.")

        # -> Send OK (ACK) to peer
        await self._write_to_source(b"\x06\x06")
        
        # <- Await source peer desired destination encrypted port
        port_encrypted_bytes = await self._receive_from_source_timeout(2, timeout)

        if not port_encrypted_bytes:
            return False
        
        port_bytes = self._decryptor.update(port_encrypted_bytes)
        port = int.from_bytes(port_bytes)

        self._log(TPDPLogType.STATUS, f"Received destination port: {port}.")

        # -- Connect to destination
        if not await self._connect_with_destination(host, port):
            return False
        
        self._log(TPDPLogType.STATUS, "Connection with destination successful.")

        # -> Send Handshake OK (ETB) to peer
        await self._write_to_source(b"\x17\x17")

        self._log(TPDPLogType.STATUS, "Handshake successful.")

        self._handshaked = True
        return True


    async def route(self, segment_size: int = 32) -> None:
        """
        Asynchronously implements the TPDP/0.1 routing processes:
            Forward source to destination:
            <- Await source peer data segment
            -- Decrypt data
            -> Forward decrypted data segment to destination peer

            Forward destination to source:
            <- Await destination peer answer data
            -- Encrypt answer data
            -> Forward encrypted answer data to source peer
        
        Arguments:
        segment_size -- Size of the segment to forward at each pass (default: 32).
        """
        if not self.is_handshaked():
            raise Exception("Can't route stream on unhandshaked connection.")

        self._log(TPDPLogType.STATUS, "Data forwarding started.")
        await asyncio.gather(
            self._forward_source_to_destination(segment_size),
            self._forward_destination_to_source(segment_size)
        )
        self._log(TPDPLogType.STATUS, f"Connection closed.")
    
    def is_handshaked(self) -> bool:
        """
        Returns whenever the connection with the source is handshaked or not.
        """
        return self._handshaked
    
    def is_closed(self) -> bool:
        """
        Returns whenever the TCP connections (with source and destination) are
        closed
        """
        return self._closed
    
    def set_log(self, flag: bool) -> None:
        """
        Set whenever the class should log information to the console.

        Arguments:
        flag -- Log toggle.
        """
        self._logging = flag
    

    # -- Private methods --
    def _log(self, type: TPDPLogType, message: str) -> None:
        """
        If log flag is set, logs message to the console.

        Arguments:
        type    -- Type of log (STATUS, INFO or ERROR).
        message -- Message to log.
        """
        if not self._logging:
            return
        
        source_host, source_port = self._source_writer.get_extra_info("peername")
        destination_host, destination_port = "N/A", "N/A"
        
        if self._destination_writer: 
            destination_host, destination_port = self._destination_writer.get_extra_info("peername")
        
        print(f"[TPDP]({source_host}:{source_port} -> {destination_host}:{destination_port})<{type.name}> - {message}")


    async def _forward_source_to_destination(self, segment_size: int) -> None:
        """
        Starts forwarding data from source to destination, removing one layer
        of encryption.

        Arguments:
        segment_size -- Size of the segment to forward at each pass.
        """
        while True:
            # <- Read data from source.
            encrypted_data = await self._source_reader.read(segment_size)

            if not encrypted_data:
                break
            
            # -- Decrypt data.
            data = self._decryptor.update(encrypted_data)
            
            # -> Send decrypted data to destination.
            self._log(TPDPLogType.INFO, f"Forwarding to destination : {data}")
            await self._write_to_destination(data)
        
        # Connection with source has been closed. Close the other.
        await self._close_connections()
        

    async def _forward_destination_to_source(self, segment_size: int) -> None:
        """
        Starts forwarding data from destination to source, adding one layer
        of encryption.

        Arguments:
        segment_size -- Size of the segment to forward at each pass.
        """
        while True:
            # <- Read data from destination.
            data = await self._destination_reader.read(segment_size)
            
            if not data:
                break
            
            # -- Encrypt data.
            encrypted_data = self._encryptor.update(data)
            
            # -> Send encrypted data to source
            self._log(TPDPLogType.INFO, f"Forwarding to source : {encrypted_data}")
            await self._write_to_source(encrypted_data)

        # Connection with destination has been closed. CLose the other.
        await self._close_connections()


    async def _close_connections(self) -> None:
        """
        Closes the TCP connections between the node and the source and destination
        peers.
        """
        if self._closed:
            return
        
        
        self._destination_writer.close()
        self._source_writer.close()
        await self._destination_writer.wait_closed()
        await self._source_writer.wait_closed()

        self._closed = True
    

    async def _receive_from_source_timeout(self, n: int, timeout: float = 10.0) -> bytes:
        """
        Returns exactly n bytes from the source peer socket data stream. If
        there is not already n bytes in the socket data stream, the function
        awaits until then OR until the timeout expires. In that case the function
        sends a TIMEOUT_ERROR to the source.

        Arguments:
        n       -- Number of bytes to read from the stream.
        timeout -- Time the function will await for the total amount of data before
                  sending TIMEOUT_ERROR.
        
        Returns:
        Received n bytes.
        """
        try:
            data = await asyncio.wait_for(self._source_reader.readexactly(n), timeout)
        except TimeoutError:
            await self._write_error_to_source(TPDPError.TIMEOUT_ERROR)
            return None
        except asyncio.IncompleteReadError:
            # Stream has been closed by source. Sending error to peer is useless
            return None
        
        return data


    async def _write_to_source(self, data: bytes) -> None:
        """
        Writes data to source and awaits stream writer to drain completely.

        Arguments:
        data -- Data to write into source stream.
        """
        self._source_writer.write(data)
        await self._source_writer.drain()


    async def _write_error_to_source(self, error: TPDPError) -> None:
        """
        Writes a single byte of error code to source stream.

        Arguments:
        error -- Error to send to source.
        """
        await self._write_to_source(error.value.to_bytes(1))
        self._log(TPDPLogType.ERROR, f"Error sent to source: {error.name}")


    async def _write_to_destination(self, data: bytes) -> None:
        """
        Writes data to destination and awaits stream writer to drain completely.

        Arguments:
        data -- Data to write into destination stream.
        """
        self._destination_writer.write(data)
        await self._destination_writer.drain()


    async def _connect_with_destination(self, host: str, port: int) -> bool:
        """
        Tries to connect to destination and returns a success flag. If the function
        was not able to connect, it also sends a DESTINATION_CONNECTION_ERROR to
        the source.

        Arguments:
        host - Hostname of the destsination.
        port - destination's TCP port on which the node should connect.

        Returns:
        Connection success.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except:
            await self._write_error_to_source(TPDPError.DESTINATION_CONNECTION_ERROR)
            return False
        
        self._destination_reader = reader
        self._destination_writer = writer
        return True



class TPDPClient:
    def __init__(self, node_reader: asyncio.StreamReader, node_writer: asyncio.StreamWriter) -> None:
        """
        TorPyDo Protocol (TPDP) handling class for client peers.

        Arguments:
        node_reader -- Socket stream reader of the first node TCP connection.
        node_writer -- Socket stream writer of the first node TCP connection.
        """
        # (public) Protocol version.
        self.version = "0.1"

        # (private) Socket stream reader/writer of the node TCP connection.
        self._node_reader = node_reader
        self._node_writer = node_writer

        # (private) AES256-CTR Ciphers, Encryptors and Decryptors
        self._ciphers = []
        self._encryptors = []
        self._decryptors = []
    

    # -- Public Methods --
    async def next_handshake(self, destination_hostname: str, destination_port: int) -> None:
        """
        Performs a TPDP/0.1 handshake process:
            -> Send source peer Hello to node
            <- Await node Hello
            -- Generate source peer X25519 private key
            -> Send source peer X25519 public key
            <- Await node X25519 public key from node
            -- Calculate X25519 shared key and derive a useable key via HKDF
            -> Send source peer randomly generated nonce for AES256/CTR cipher
            -- Create AES256/CTR cipher instance
            <- Await OK (ACK) from node or error code
            -> Send source peer desired destination encrypted hostname length
            -> Send source peer desired destination encrypted hostname
            <- Await OK (ACK) from node
            -> Send source peer desired destination encrypted port
            <- Await Handshake OK (ETB) from node
        
        Arguments:
        destination_hostname -- Hostname of the node destination.
        destination_port     -- TCP Port of the node destination.
        """
        # -> Send peer Hello to node
        await self._write_to_node(b"Hello TPDP/0.1\r\n")

        # <- Await node Hello
        hello_data = await self._receive_from_node(16)

        if hello_data != b"Hello TPDP/0.1\r\n":
            raise Exception("Node commited a protocol error during handshake")

        # -- Generate source peer X25519 private key
        private_key = X25519PrivateKey.generate()

        # -> Send peer X25519 public key to node
        await self._write_to_node(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

        # <- Await source peer X25519 public key
        node_public_key_bytes = await self._receive_from_node(32)
        
        node_public_key = X25519PublicKey.from_public_bytes(node_public_key_bytes)

        # -- Calculate X25519 shared key and derive a useable key via HKDF
        shared_key = private_key.exchange(node_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"TPDP/0.1").derive(shared_key)
        
        # -> Send source peer randomly generated nonce for AES256/CTR cipher
        ctr_nonce = token_bytes(16)
        await self._write_to_node(ctr_nonce)

        # -- Create AES256/CTR cipher instance
        cipher = Cipher(AES256(derived_key), CTR(ctr_nonce))
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()

        # <- Await OK (ACK) from node
        ack_data = await self._receive_from_node(2)

        if ack_data != b"\x06\x06":
            raise Exception("Node commited a protocol error during handshake")
        
        # -> Send source peer desired destination encrypted hostname length
        await self._write_to_node(len(destination_hostname).to_bytes(2))

        # -> Send source peer desired destination encrypted hostname
        host_encrypted_bytes = encryptor.update(destination_hostname.encode())
        await self._write_to_node(host_encrypted_bytes)

        # <- Await OK (ACK) from node
        ack_data = await self._receive_from_node(2)

        if ack_data != b"\x06\x06":
            raise Exception("Node commited a protocol error during handshake")

        # -> Send source peer desired destination encrypted port
        port_encrypted_bytes = encryptor.update(destination_port.to_bytes(2))
        await self._write_to_node(port_encrypted_bytes)
        
        # <- Await Handshake OK (ETB) from node
        handshake_ok = await self._receive_from_node(2)

        if handshake_ok != b"\x17\x17":
            raise Exception("Node commited a protocol error during handshake")
        
        self._ciphers.append(cipher)
        self._encryptors.append(encryptor)
        self._decryptors.append(decryptor)
        return True
    

    async def send(self, data: bytes) -> None:
        """ 
        Sends data to final destination.
        
        Arguments:
        data -- Data to send.
        """
        await self._write_to_node(data)
    

    async def receive(self, buffer_size: int) -> bytes:
        """
        Receives data from final_destination.

        Arguments:
        buffer_size -- Max bytes to receive.

        Returns:
        Received decrypted data
        """
        # <- Read encrypted data from node
        encrypted_data = await self._node_reader.read(buffer_size)
        
        # -- Decrypt data
        data = encrypted_data
        for i in range(len(self._decryptors)):
            data = self._decryptors[i].update(data)
        
        return data
    
    async def receive_exactly(self, n: int) -> bytes:
        """
        Receives exactly n bytes from final_destination.

        Arguments:
        n -- bytes to receive.

        Returns:
        Received decrypted data
        """
        # <- Read encrypted data from node
        encrypted_data = await self._node_reader.readexactly(n)
        
        # -- Decrypt data
        data = encrypted_data
        for i in range(len(self._decryptors)):
            data = self._decryptors[i].update(data)
        
        return data


    # -- Private methods --
    async def _write_to_node(self, data: bytes) -> None:
        """
        Writes a n time encrypted message, where n is the number of node between
        the client and the final destination.

        Arguments:
        data -- Data to write.
        """
        # -- Encrypt data
        for i in range(len(self._encryptors)-1, -1, -1):
            data = self._encryptors[i].update(data)
        
        # -> Send encrypted data to node
        self._node_writer.write(data)
        await self._node_writer.drain()
        
    

    async def _receive_from_node(self, n: int) -> bytes:
        """
        Returns exactly n bytes from the node socket data stream. If
        there is not already n bytes in the socket data stream, the function
        awaits until then.
        If EOF is crossed before n bytes were read, raises an ERROR with last
        received byte as error code.

        Arguments:
        n -- Number of bytes to read from the stream.

        Returns:
        Received n bytes
        """
        # Read exactly n bytes
        try:
            data = await self._node_reader.readexactly(n)
        except asyncio.IncompleteReadError as error:
            # Extract the error code.
            if not error.partial:
                raise EOFError("Connection with node closed: Unspecified error.")
            
            error_code = error.partial[-1:]
            for i in range(len(self._decryptors)):
                error_code = self._decryptors[i].update(error_code)
            
            raise EOFError(f"Connection with noe closed: {TPDPError(error_code[0]).name}.")
        
        # Decrypt data
        for i in range(len(self._decryptors)):
            data = self._decryptors[i].update(data)

        return data
