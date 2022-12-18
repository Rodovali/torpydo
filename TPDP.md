TorPyDo Protocol 0.1 (TPDP/0.1) Specifications
==============================================

**Version:** 0.1
**Date:** 10/12/2022
**Authors:** Rodolphe VALICON, Andrei ANGHEL-PANTELIMON, Mouhidin MAHMALJI and 
Bao HAN.

## Introduction and definitions
Torpydo is a stream based peer-to-peer decentralized onion routing platform 
written in Python. Its goal is to anonymize end-to-end TCP connections, relying 
on multiple encryptions of the TCP stream segments (like an onion) and on a 
particular peer-to-peer architecture where nodes don't know anything about the
nature of their source and destination and about the data segments they are 
forwarding.

Anonymity is further guaranteed thanks to the stream ciphers used. 
Disabling nodes to know their role in the chain (no un-padding).

TorPyDo Protocol or TPDP is the protocol on which Torpydo is built.

In this specification we will use the following denominations:
- **Node** - A server hosting a TPDP service.
- **Client** - A client sending data through a TPDP interface.
- **Final Destination** - The destination the client wants to reach anonymously
through the torpydo network.
- **Source** - The peer just before a particular node (can be a client or 
another node).
- **Destination** - The peer just after a particular node (can be a final
destination or another node).

## Working Principle
A torpydo network is constituted of a certain number of independant nodes.
When a client wants to reach anonymously a final destination, it first choose
a set of nodes. It then constructs a path from itself to its final destination
through the chosen nodes. To do so, it contacts the first node, exchanges a
shared key and communicates the address of the second node. It then do the same
with the second node through the first one. The process is repeated until the
final destination is reached by the last node.

At each step, a encryption level is added. The client encrypts the data it want
to send with the keys of the intermediate nodes. When data is forwarded by a
node it is first decrypted one time with the key of the node.

When data is sent back by the final destination, the data is encrypted one time
with the nodes keys at each forwarding step.
As the client is the only entity in the chain to have all the keys, it is also
the only one able to decrypt the data completely at the end of the chain.

The chain lasts until the client or the final destination cuts the TCP 
connection. This results to the total destruction of the chain (all the TCP
connections are closed). This can also happen if an intermediate node cut the
connection for a reason or another.

## TPDP Session
A TPDP session is divided in two phases:
- Handshake
- Data forwarding

During **handshake**, the client and the node will exchange a shared key, to 
encrypt and decrypt data. Then the client communicates to the node its 
destination host name and port, on which the node tries to connect. If the 
connection is successful, the session enter the data forwarding phase.

During the **data forwarding** phase, every data segment received from the 
source are decrypted and forwarded to the destination. Similarly, every data 
segment received from the destination are encrypted and forwarded to the source.

### Handshake
For a node, the handshake protocol is:
```
<- Await source peer Hello (16 bytes)
-> Send node Hello to source peer (16 bytes)
-- Generate node 256bits X25519 private key
<- Await source peer 256bits X25519 public key (32 bytes)
-> Send node X25519 public key to peer (32 bytes)
-- Calculate 256bits X25519 shared key and derive a useable 256bits key via HKDF
<- Await source peer randomly generated nonce for AES256/CTR cipher (16 bytes)
-- Create AES256/CTR cipher instance
-> Send OK (ACK) to peer (2 bytes)
<- Await source peer desired destination encrypted hostname length (2 bytes)
<- Await source peer desired destination encrypted hostname (x bytes)
-> Send OK (ACK) to peer (2 bytes)
<- Await source peer desired destination encrypted port (2 bytes)
-- Connect to destination
-> Send Handshake OK (ETB) or error code to peer (2 bytes)
```

For a client, the handshake protocol is:
```
-> Send source peer Hello (16 bytes)
<- Await node Hello to source peer (16 bytes)
-- Generate node 256bits X25519 private key
-> Send source peer 256bits X25519 public key (32 bytes)
<- Await node 256bits X25519 public key from node (32 bytes)
-- Calculate 256bits X25519 shared key and derive a useable 256bits key via HKDF
-> Send source peer randomly generated a nonce for AES256/CTR cipher (16 bytes)
-- Create AES256/CTR cipher instance
<- Await OK (ACK) from node or error code (2 bytes)
-> Send source peer desired destination encrypted hostname length (2 bytes)
-> Send source peer desired destination encrypted hostname (x bytes)
<- Await OK (ACK) from node (2 bytes)
-> Send source peer desired destination encrypted port (2 bytes)
<- Await Handshake OK (ETB) from node (2 bytes)
```

- The Hello message should be `Hello TPDP/0.1\r\n`.
- ACK corresponds to a `\x06\x06` (two Acknowledge characters).
- ETB corresponds to a `\x17\x17` (two End of Transmission Block characters).

Any difference with these messages will result to a `PROTOCOL_ERROR` followed
by an immediate disconnection.

Additionally a timeout (10s by default) can be set by the node administrator.
If the node awaits for a client response during the handshake for more than the
timeout, it will result to a `TIMEOUT_ERROR` followed by an immediate
disconnection.

### Data Forwarding
For a node, data forwarding is made in two asynchronous pocesses:
Forward source data to destination:
```
<- Await source peer data segment
-- Decrypt data
-> Forward decrypted data segment to destination peer
```
Forward destination data to source:
```
<- Await destination peer answer data
-- Encrypt answer data
-> Forward encrypted answer data to source peer
```

For a client:
Send data to final destination:
```
-- Encrypt data with all the nodes keys (in order from last key to first key)
-> Send data to first node
```
Receive data from final destination:
```
<- Receive data from the first node
-- Decrypt data with all the nodes keys (in order from first key to last key)
```

All these processes are executed until the TCP connection is closed by the
client, the final destination, or by any intermediate node for a reason or
another.

## TPDP Error handling
Errors can happen during the handshake phase. Here is a list of all the
possible errors, with their code and their signification:
- `TIMEOUT_ERROR`: 0 - Client took too much time to do a handshake step.
- `PROTOCOL_ERROR`: 1 - Node or Client did not respected the protocol.
- `DESTINATION_CONNECTION_ERROR`: 2 - Node was not able to connect with the
destination.

When an error is throwed by a node, it sends a byte corresponding to the error
code to the client, and immediately cut the connection. Hence the client can
get the error code by looking at the last byte of the stream.
When an error is throwed by a client, it cuts the connection and raises an 
exception.
