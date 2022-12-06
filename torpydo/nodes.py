# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Torpydo Library - Nodes
# Description: Entry, Relay and Exit Nodes classes for Torpydo
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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
# HMAC-based Extract-and-Expand Key Derivation Function
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# 256 bits Advanced Encryption Standard with Cipher Block Chaining algorithm
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CBC


# === Classes ===
# - Nodes -
class NodeType(Enum):
    NONE = 0
    ENTRY = 1
    RELAY = 2
    EXIT = 3

class Node:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.type = NodeType.NONE
        ...
    
class EntryNode(Node):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(host, port)
        self.type = NodeType.ENTRY
        ...

class RelayNode(Node):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(host, port)
        self.type = NodeType.RELAY
        ...

class ExitNode(Node):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(host, port)
        self.type = NodeType.EXIT
        ...
