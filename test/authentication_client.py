# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Authentication Client Test
# Description: Challenge-response authentication
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
import asyncio
from torpydo.client import Client

# Enumerations
from enum import Enum

#
from secrets import token_bytes

# Elliptic curve Diffie-Hellman key exchange algorithm
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
# Key serialization config enums
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# HMAC-based Extract-and-Expand Key Derivation Function
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# 256 bits Advanced Encryption Standard with Counter mode
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CTR

# === CONFIG ===
SERVER_HOST = "127.0.0.1" # Address of authentication server
SERVER_PORT = 8989 # Port of authentication server

POOL_INDEX_HOST = "127.0.3.2" # Address of a torpydo pool index server
POOL_INDEX_PORT = 8080       # Port of a torpydo pool index server

PATH_LENGTH = 1 # Number of nodes separating the client and the destination server


# === Enums ===
class ServerError(Enum):
    TIMEOUT_ERROR = 0
    PROTOCOL_ERROR = 1
    PASSWORD_ERROR = 2

# === Function ===
async def receive_from_server(torpydo: Client, n: int) -> bytes:
        """
        Returns exactly n bytes from the server socket data stream. If
        there is not already n bytes in the socket data stream, the function
        awaits until then.
        If EOF is crossed before n bytes were read, raises an ERROR with last
        received byte as error code.

        Arguments:
        server_reader -- Stream reader of the the server TCP socket.
        n -- Number of bytes to read from the stream.

        Returns:
        Received n bytes
        """
        # Read exactly n bytes
        try:
            data = await torpydo.receive_exactly(n)
        except asyncio.IncompleteReadError as error:
            # Extract the error code.
            if not error.partial:
                raise EOFError("Connection with server closed: Unspecified error.")
            
            error_code = error.partial[-1:]
            
            raise EOFError(f"Connection with noe closed: {ServerError(error_code[0]).name}.")
        
        return data

async def handshake(torpydo: Client) -> Cipher:
    """
    Performs a handshake process:
        -> Send client Hello
        <- Await server Hello
        -- Generate client X25519 private key
        -> Send client X25519 public key
        <- Await server X25519 public key from server
        -- Calculate X25519 shared key and derive a useable key via HKDF
        -> Send client randomly generated nonce for AES256/CTR cipher
        -- Create AES256/CTR cipher instance
        <- Await Handshake OK (ACK) from server
    
    Arguments:
    server_reader -- Stream reader of server TCP socket stream
    server_writer -- Stream writer of server TCP socket stream

    Returns:
    Handshake generated cipher if handshake succeeded or None
    """
        
    # -> Send peer Hello to server
    await torpydo.send(b"Hello AUTHSERV\r\n")
    

    # <- Await source server Hello
    hello_data = await receive_from_server(torpydo, 16)

    if hello_data != b"Hello AUTHSERV\r\n":
        raise Exception("Server commited a protocol error during handshake")

    # -- Generate client X25519 private key
    private_key = X25519PrivateKey.generate()

    # -> Send peer X25519 public key to server
    await torpydo.send(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


    # <- Await source peer X25519 public key
    server_public_key_bytes = await receive_from_server(torpydo, 32)
    
    server_public_key = X25519PublicKey.from_public_bytes(server_public_key_bytes)

    # -- Calculate X25519 shared key and derive a useable key via HKDF
    shared_key = private_key.exchange(server_public_key)
    derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"TPDP/0.1").derive(shared_key)
    
    # -> Send source server randomly generated nonce for AES256/CTR cipher
    ctr_nonce = token_bytes(16)
    await torpydo.send(ctr_nonce)

    # -- Create AES256/CTR cipher instance
    cipher = Cipher(AES256(derived_key), CTR(ctr_nonce))

     # <- Await OK (ACK) from server
    ack_data = await receive_from_server(torpydo, 2)

    if ack_data != b"\x06\x06":
        raise Exception("Server commited a protocol error during handshake")

    return cipher

async def authenticate(torpydo: Client, encryptor: CipherContext, password: str) -> None:
    # Send password
    encrypted_password = encryptor.update(password.encode() + b"\x00")
    await torpydo.send(encrypted_password)


    # Await answer
    ack_data = await receive_from_server(torpydo, 2)

    if ack_data != b"\x06\x06":
        raise Exception("Server commited a protocol error")

async def receive_secret_data(torpydo: Client, decryptor: CipherContext) -> bytes:
    data = b""
    while True:
        chunk = await torpydo.receive(1024)
        if not chunk:
            break
        
        data += decryptor.update(chunk)
    
    return data


async def main():
    torpydo = Client()
    await torpydo.sync_nodes_list(POOL_INDEX_HOST, POOL_INDEX_PORT)
    await torpydo.random_path_to_destination(SERVER_HOST, SERVER_PORT, PATH_LENGTH)
    print("Connected to server through torpydo!")
    cipher = await handshake(torpydo)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    print("Handshake with server succesful!")
    password = input("Password: ")
    await authenticate(torpydo, encryptor, password)
    print("Authentication successful!")
    secret_data = await receive_secret_data(torpydo, decryptor)
    print(f"Received secret data: {secret_data}")

if __name__ == "__main__":
    asyncio.run(main())
