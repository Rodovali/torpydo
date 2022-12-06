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
# - Client -
class Client():
    def __init__(self) -> None:
        ...

