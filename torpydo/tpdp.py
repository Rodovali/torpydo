# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - TPDP interface
# Description: TorPyDo Protocol (TPDP) interface providing high-level methods
#              for interacting between peers
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
# Asynchronous tasking and networking
import asyncio

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
# Block padding algorithm
from cryptography.hazmat.primitives.padding import PKCS7
# 256 bits Advanced Encryption Standard with Counter mode
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CTR


# === Enums ===
class TPDPError(Enum):
    TIMEOUT_ERROR = 0
    PROTOCOL_ERROR = 1
    DESTINATION_CONNECTION_ERROR = 2

# === Classes ===
class TPDPService:
    """
    TorPyDo Protocol (TPDP) handling class for serving peers (nodes).
    Provides high-level methods for interacting with source and destination peers
    """
    def __init__(self, source_reader: asyncio.StreamReader, source_writer: asyncio.StreamWriter) -> None:
        self.version = "0.1"

        self._source_reader = source_reader
        self._source_writer = source_writer

        self._destination_reader = None
        self._destination_writer = None

        self._cipher = None
        self._encryptor = None
        self._decryptor = None

        self.handshaked = False

    async def handshake(self, timeout: float = 10.0) -> bool:
        """
        Implements the TPDP/0.1 handshake process:
            <- Await source peer Hello
            -> Send node Hello to source peer
            -- Generate node X25519 private key
            <- Await source peer X25519 public key
            -> Send node X25519 public key to peer
            -- Calculate X25519 shared key and derive a useable key via HKDF
            <- Await source peer randomly generated nounce for AES256/CTR cipher
            -- Create AES256/CTR cipher instance
            -> Send OK (ACK) to peer
            <- Await source peer desired destination encrypted hostname ending by \x03 (End of text)
            -> Send OK (ACK) to peer
            <- Await source peer desired destination encrypted port
            -- Connect to destination
            -> Send Handshake OK (ETB) to peer
        """
        # <- Await source peer Hello
        hello_data = await self._receive_from_source_timeout(16, timeout)

        if not hello_data:
            return False
        elif hello_data != b"Hello TPDP/0.1\r\n":
            await self._write_error_to_source(TPDPError.PROTOCOL_ERROR)
            return False
        
        # -> Send node Hello to peer
        await self._write_to_source(b"Hello TPDP/0.1\r\n")

        # -- Generate node X25519 private key
        private_key = X25519PrivateKey.generate()

        # <- Await source peer X25519 public key
        peer_public_key_bytes = await self._receive_from_source_timeout(32, timeout)

        if not peer_public_key_bytes:
            return False
        
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

        # -> Send node X25519 public key to peer
        await self._write_to_source(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

        # -- Calculate X25519 shared key and derive a useable key via HKDF
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None).derive(shared_key)

        # <- Await source peer randomly generated nounce for AES256/CTR cipher
        ctr_nounce = await self._receive_from_source_timeout(16, timeout)

        if not ctr_nounce:
            return False
        
        # -- Create AES256/CTR cipher instance
        self._cipher = Cipher(AES256(derived_key), CTR(ctr_nounce))
        self._encryptor = self._cipher.encryptor()
        self._decryptor = self._cipher.decryptor()

        # -> Send node ACK to peer
        await self._write_to_source(b"\x06")

        # <- Await source peer desired destination encrypted hostname ending by \x03 (End of text)
        host_encrypted_bytes = await self._receive_from_souce_until_byte_timeout(0x03, timeout)

        if not host_encrypted_bytes:
            return False
        
        host_bytes = self._decryptor.update(host_encrypted_bytes)
        host = host_bytes[0:-1].decode()

        # -> Send OK (ACK) to peer
        await self._write_to_source(b"\x06")
        
        # <- Await source peer desired destination encrypted port
        port_encrypted_bytes = await self._receive_from_source_timeout(2, timeout)

        if not port_encrypted_bytes:
            return False
        
        port_bytes = self._decryptor.update(port_encrypted_bytes)
        port = int.from_bytes(port_bytes)
        
        # -- Connect to destination
        if not await self._connect_with_destination(host, port):
            return False
        
        # -> Send Handshake OK (ETB) to peer
        await self._write_to_source(b"\x06")

        self.handshaked = True
        return True


    async def route(self) -> None:
        """
        Implements the TPDP/0.1 routing process:
            <- Await source peer data segment
            -- Decrypt data
            -> Forward decrypted data segment to destination peer

            And asyncronously with first process
            <- Await destination peer answer data
            -- Encrypt answer data
            -> Forward encrypted answer data to source peer 
        """

    async def _receive_from_source(self, n: int) -> bytes:
        """
        Ensure reading exactly n bytes from the source peer socket data stream.
        """
        data = b""

        while len(data) < n:
            chunk = await self._source_reader.read(n - len(data))
            if not chunk:
                raise Exception("Source stream closed")
            data += chunk

        return data
    
    async def _receive_from_source_timeout(self, n: int, timeout: float = 10.0) -> bytes:
        """
        Ensure reading exactly n bytes from the source peer socket data stream with a timeout.
        """
        try:
            data = await asyncio.wait_for(self._receive_from_source(n), timeout)
        except TimeoutError:
            await self._write_error_to_source(TPDPError.TIMEOUT_ERROR)
            return None
        except Exception:
            # Stream has been closed. Sending error to peer is useless
            return None
        
        return data

    async def _receive_from_source_until_byte(self, end_byte: int) -> bytes:
        """
        Read source peer socket stream until byte with value end_byte encountered.
        Only works if end_byte is the last byte of the socket stream.
        """
        data = b""

        while data[-1] != end_byte:
            chunk = await self._source_reader.read(32)
            if not chunk:
                raise Exception("Source stream closed")
            data += chunk
        
        return data
    
    async def _receive_from_souce_until_byte_timeout(self, end_byte: int, timeout: float = 10.0) -> bytes:
        """
        Read source peer socket stream until byte with value end_byte encountered with a timeout.
        Only works if end_byte is the last byte of the socket stream.
        """
        try:
            data = await asyncio.wait_for(self._receive_from_source_until_byte(end_byte), timeout)
        except TimeoutError:
            await self._write_error_to_source(TPDPError.TIMEOUT_ERROR)
            return None
        except Exception:
            # Stream has been closed. Sending error to peer is useless
            return None
        
        return data

    async def _write_to_source(self, data: bytes) -> None:
        self._source_writer.write(data)
        await self._source_writer.drain()
    
    async def _write_error_to_source(self, error: TPDPError) -> None:
        await self._write_to_source(f"ERROR {error.value} TPDP/0.1".encode())

    async def _write_to_destination(self, data: bytes) -> None:
        self._destination_writer.write(data)
        await self._destination_writer.drain()

    async def _connect_with_destination(self, host: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except:
            await self._write_error_to_source(TPDPError.DESTINATION_CONNECTION_ERROR)
            return False
        
        self._destination_reader = reader
        self._destination_writer = writer
        return True

    async def _forward_to_destination(self) -> None:
        ...
    
    async def _forward_to_source(self) -> None:
        ...

class TPDPClient:
    ...