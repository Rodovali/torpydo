# Torpydo simple http proxy

# === Libraries ===
import asyncio
from torpydo.client import Client

# === Config ===
PROXY_HOST = "127.0.0.1"    # Address on which the proxy server is listening.
PROXY_PORT = 8686           # TCP port on which the proxy server is listening.

POOL_INDEX_HOST = "127.0.3.2" # 
POOL_INDEX_PORT = 8080

PATH_LENGTH = 1

# === Functions ===
async def handle_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    host = None;
    port = 80;
    
    # Receive a GET request and extract recipient hostname/port
    request_line_bytes = await reader.readuntil(b"\r\n");
    request_line_words = str.split(request_line_bytes.decode(), " ")
    host_port = str.split(str.split(request_line_words[1], "/")[2], ":")
    host = host_port[0]
    if len(host_port) == 2:
        port = int(host_port[1])
    
    # Instanciate torpydo client and connect to recipient through network
    # then 
    client = Client()
    try:
        await client.sync_nodes_list(POOL_INDEX_HOST, POOL_INDEX_PORT)
        await client.random_path_to_destination(host, port, PATH_LENGTH)
        await client.send(request_line_bytes)
        await asyncio.gather(
            forward_request(reader, client),
            forward_answer(writer, client)
        )
    finally:
        writer.close()
        await writer.wait_closed()

async def forward_request(client_reader: asyncio.StreamReader, torpydo_client: Client) -> None:
    while True:
        try:
            data = await client_reader.read(1024)
            await torpydo_client.send(data)
        except:
            return


async def forward_answer(client_writer: asyncio.StreamWriter,  torpydo_client: Client) -> None:
    while True:
        try:
            data = await torpydo_client.receive(1024)
            client_writer.write(data)
            await client_writer.drain()
        except:
            return

async def start_proxy(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_request, host, port)
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_proxy(PROXY_HOST, PROXY_PORT))
