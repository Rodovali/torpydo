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

class TPDPError(Enum):
    HANDSHAKE_TIMEOUT_ERROR = 0
    PROTOCOL_ERROR = 1

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

    async def handshake(self) -> bool:
        """
        Implements the TPDP/0.1 handshake process:
            <- Await source peer Hello
            -> Send node Hello to peer
            -- Generate node X25519 private key
            <- Await source peer X25519 public key
            -> Send node X25519 public key
            -- Calculate X25519 shared key and derive a useable key via HKDF
            <- Await source peer randomly generated nounce for AES256/CTR cipher
            -- Create AES256/CTR cipher instance
            -> Send node OK
            <- Await source peer desired destination encrypted hostname ending by \x03 (End of text)
            -> Send node OK
            <- Await source peer desired destination encrypted port
            -- Connect to destination
            -> Send node Handshake OK
        """
        ...

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
        ...

    async def _receive_from_source(self, n: int) -> bytes:
        data = b""

        while len(data) < n:
            data += await self._source_reader.read(n - len(data))
        
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
        ...

    async def _forward_to_destination(self) -> None:
        ...
    
    async def _forward_to_source(self) -> None:
        ...

class TPDPClient:
    ...