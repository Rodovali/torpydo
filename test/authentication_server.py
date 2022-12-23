# -*- coding: utf-8 -*-
# ==============================================================================
# Title: Authentication Server Test
# Description: Challenge-response authentication
# Authors: Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidir MAHMALJI,
#          Bao HAN
#===============================================================================

# === Libraries ===
# Asynchronous tasking and networking
import asyncio

# Enumerations
from enum import Enum

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

# === Config ===
HOST = "127.0.0.1"
PORT = 8989

# === Enums ===
class ServerError(Enum):
    TIMEOUT_ERROR = 0
    PROTOCOL_ERROR = 1
    PASSWORD_ERROR = 2

class ServerLogType(Enum):
    INFO = 0
    STATUS = 1
    ERROR = 2

# === Classes ===
class AuthenticationServer:
    def __init__(self, host: str, port: int) -> None:
        """
        Authentication server.

        Arguments:
        host -- Address of the server.
        port -- TCP port on which the servers should connect.
        """
        # (private) Listening address
        self._host = host
        # (private) Listening TCP port
        self._port = port

        # (private) Asyncio server instance
        self._server = None

        # (private) Logging flag
        self._logging = False

        # (private) Hashed server password: SHA256 hash of "test_password123"
        self._password_hash = b"\x06\x99\x8e\x1b\x93>\x06\xfb\x1a;\\\x1c\xbb\xd4\x0c\xe6\x10\xfc\x8d\xaa\xf8o\x1d\x08\xd0\xdfRD{\x14D\x9f"

        # (private) Server super secret data, that only authed clients should see
        self._super_secret_data = b"I'm a super secret sentence mwahaha."
    
    # -- Public methods --    
    async def start(self) -> None:
        """
        Creates a TCP socket to listen for connections.
        """
        self._server = await asyncio.start_server(self._handle_connection, self._host, self._port)
        self._log(ServerLogType.STATUS, f"Server is listening on {self._host}:{self._port}.")
        
        await self._server.serve_forever()

    def set_log(self, flag: bool) -> None:
        """
        Set whenever the server should log information to the console.

        Arguments:
        flag -- Logging toggle.
        """
        self._logging = flag


    # -- Private methods --
    async def _handle_connection(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """
        Handles a client connection to the server: Makes an handshake, authenticates
        the client and sends the super data to authed client.

        Arguments:
        client_reader -- Stream reader of client TCP socket stream
        client_writer -- Stream writer of client TCP socket stream
        """

        # Handshake with client
        cipher = await self._handshake(client_reader, client_writer)
        
        # Check if handshake was successful
        if not cipher:
            client_writer.close()
            await client_writer.wait_closed()
            return
        
        # Instanciate an encrypting and a decrypting cipher contexts
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        
        # Authenticate client
        authentication_success = await self._authenticate(client_reader, decryptor)
        # Check if authentication wass successful
        if not authentication_success:
            await self._write_error(client_writer, ServerError.PASSWORD_ERROR)
            client_writer.close()
            await client_writer.wait_closed()
            return
        
        # Send ACK to client
        client_writer.write(b"\x06\x06")
        await client_writer.drain()
        # Send encryted super secret server data to authed client
        await self._send_secret_data(client_writer, encryptor)

        # Close connection with client
        client_writer.close()
        await client_writer.wait_closed()
        return

        
    

    async def _handshake(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, timeout: float = 10.0) -> Cipher:
        """
        Await for a client hello and proceed with a handshake:
            <- Await client Hello
            -> Send server Hello to client
            -- Generate server X25519 private key
            <- Await client X25519 public key
            -> Send server X25519 public key to client
            -- Calculate X25519 shared key and derive a useable key via HKDF
            <- Await client randomly generated nonce for AES256/CTR cipher
            -- Create AES256/CTR cipher instance
            -> Send OK (ACK) to client
        
        Arguments:
        client_reader -- Stream reader of client TCP socket stream
        client_writer -- Stream writer of client TCP socket stream
        timeout -- Time (in s) the server will await at each step before cutting
                   the connection with the client (default 10.0).

        Returns:
        Handshake generated cipher if handshake succeeded or None
        """
        # <- Await client Hello
        hello_data = await self._receive_timeout(client_reader, client_writer, 16, timeout)

        if not hello_data:
            return False
        elif hello_data != b"Hello AUTHSERV\r\n":
            await self._write_error(client_writer, ServerError.PROTOCOL_ERROR)
            return False
        
        self._log(ServerLogType.STATUS, "Handshake start.")

        # -> Send server Hello to client
        client_writer.write(b"Hello AUTHSERV\r\n")
        await client_writer.drain()

        # -- Generate server X25519 private key
        private_key = X25519PrivateKey.generate()

        self._log(ServerLogType.STATUS, "Private key generated.")

        # <- Await client X25519 public key
        client_public_key_bytes = await self._receive_timeout(client_reader, client_writer, 32, timeout)
        
        if not client_public_key_bytes:
            return False
        
        client_public_key = X25519PublicKey.from_public_bytes(client_public_key_bytes)

        self._log(ServerLogType.STATUS, f"Received client public key: {client_public_key_bytes}.")

        # -> Send server X25519 public key to client
        client_writer.write(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        await client_writer.drain()

        # -- Calculate X25519 shared key and derive a useable key via HKDF
        shared_key = private_key.exchange(client_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"TPDP/0.1").derive(shared_key)

        self._log(ServerLogType.STATUS, "Key exchange complete.")

        # <- Await client randomly generated nonce for AES256/CTR cipher
        ctr_nonce = await self._receive_timeout(client_reader, client_writer, 16, timeout)

        if not ctr_nonce:
            return False
        
        self._log(ServerLogType.STATUS, f"Received encryption nonce: {ctr_nonce}.")

        # -- Create AES256/CTR cipher instance
        cipher = Cipher(AES256(derived_key), CTR(ctr_nonce))

        self._log(ServerLogType.STATUS, "Cipher configured.")

        # -> Send server ACK to client
        client_writer.write(b"\x06\x06")
        await client_writer.drain()

        return cipher

    
    async def _authenticate(self, client_reader: asyncio.StreamReader, decryptor: CipherContext, timeout: float = 10.0,) -> bool:
        """
        Receives a password from the client, decrypts it, hashes it, and compares it with the stored hashed password
        if the two hashes are equal, the authentication is successful and the function returns True.

        Arguments:
        client_reader -- Stream reader of client TCP socket stream
        decryptor -- Decryptor cipher context
        
        Returns:
        Whether the authentication was successful or not
        """
        password = b""
        while True:
            try:
                password_encrypted_chunk = await asyncio.wait_for(client_reader.read(1024), timeout)
            except asyncio.TimeoutError:
                return False

            password_chunk = decryptor.update(password_encrypted_chunk)
            password += password_chunk
            if password[-1] == 0:
                password = password[:-1]
                break
        
        digest = Hash(SHA256())
        digest.update(password)
        hashed_password = digest.finalize()

        return hashed_password == self._password_hash
        

    async def _send_secret_data(self, client_writer: asyncio.StreamWriter, encryptor: CipherContext) -> None:
        """
        Sends the super secret server data to the client, encrypted with the shared key.

        Arguments:
        client_writer -- Stream writer of client TCP socket stream
        encryptor -- Encrypting CipherContext
        """
        encrypted_super_secret_data = encryptor.update(self._super_secret_data)

        client_writer.write(encrypted_super_secret_data)
        await client_writer.drain()


    async def _receive_timeout(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, n: int, timeout: float = 10.0) -> bytes:
        """
        Returns exactly n bytes from the client socket data stream. If
        there is not already n bytes in the socket data stream, the function
        awaits until then OR until the timeout expires. In that case the function
        sends a TIMEOUT_ERROR to the source.

        Arguments:
        client_reader -- Stream reader of the client TCP socket stream.
        client_writer -- Stream writer of the client TCP socket stream.
        n             -- Number of bytes to read from the stream.
        timeout       -- Time the function will await for the total amount of 
                         data before sending TIMEOUT_ERROR.
        
        Returns:
        Received n bytes.
        """
        try:
            data = await asyncio.wait_for(client_reader.readexactly(n), timeout)
        except TimeoutError:
            await self._write_error(client_writer, ServerError.TIMEOUT_ERROR)
            return None
        except asyncio.IncompleteReadError:
            # Stream has been closed by client. Sending error to client is useless
            return None
        
        return data


    async def _write_error(self, client_writer: asyncio.StreamWriter, error: ServerError) -> None:
        """
        Writes a single byte of error code to client stream.

        Arguments:
        client_writer -- Stream writer of the client TCP socket stream.
        error         -- Error to send to client.
        """
        client_host, client_port = client_writer.get_extra_info("peername")

        client_writer.write(error.value.to_bytes(1))
        await client_writer.drain()
        self._log(ServerLogType.ERROR, f"({client_host}:{client_port}) Error sent to client: {error.name}")
        


    def _log(self, type: ServerLogType, message: str) -> None:
        """
        If log flag is set, logs message to the console.

        Arguments:
        type    -- Type of log (STATUS, INFO or ERROR).
        message -- Message to log.
        """
        if not self._logging:
            return

        print(f"[Server]<{type.name}> - {message}")


# === Main Code ===
if __name__ == "__main__":
    server = AuthenticationServer(HOST, PORT)
    server.set_log(True)
    asyncio.run(server.start())