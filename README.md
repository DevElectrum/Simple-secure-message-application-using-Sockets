# Secure Message App

A simple terminal-based secure client-server chat application for a Network Security extra credit project. The app uses Python sockets on `127.0.0.1:5000` and demonstrates mutual authentication, confidentiality, and message integrity.

## Features

- TCP socket client and server
- RSA key pairs for the client and server
- Mutual authentication with RSA-PSS signatures over random nonces
- AES session key transport with RSA-OAEP
- Encrypted chat messages with AES-256-GCM
- 4-byte length-prefix framing for socket messages
- Tamper demo showing message integrity failure

## Security Protocol Summary

1. The server sends a random nonce to the client.
2. The client signs the server nonce with its private key.
3. The server verifies the signature using the client's public key.
4. The client sends a random nonce to the server.
5. The server signs the client nonce with its private key.
6. The client verifies the signature using the server's public key.
7. The client generates an AES-256 session key.
8. The client encrypts the AES key with the server's RSA public key using RSA-OAEP.
9. Both sides use the shared AES key for AES-GCM encrypted chat messages.

## Setup

Create and activate a virtual environment if desired, then install dependencies:

```bash
pip install -r requirements.txt
```

## Generate Keys

Keys are generated locally and are not committed to the repository:

```bash
python generate_keys.py
```

This creates the required PEM files in `keys/`.

## Run the App

Open two terminals in the project folder.

Terminal 1:

```bash
python server.py
```

Terminal 2:

```bash
python client.py
```

Type messages in each terminal. Type `exit` from either side to close the chat.

## Tamper Demo

Run:

```bash
python tamper_demo.py
```

The demo encrypts a message, modifies one byte, and shows that AES-GCM rejects the tampered packet.

## Assignment Requirements Mapping

- Network application using sockets: `client.py`, `server.py`, and `crypto_utils.py` use Python TCP sockets.
- Mutual authentication: both sides sign and verify random nonces with RSA-PSS.
- Confidentiality: the AES session key is encrypted with RSA-OAEP, and chat messages are encrypted with AES-256-GCM.
- Message integrity: AES-GCM authentication tags detect modified encrypted packets.
- Design document with diagrams: see `DESIGN.md`.
- Working application evidence: see `DEMO_TRANSCRIPT.md`; screenshots can be added under `screenshots/`.

## Limitations

- The server accepts one client connection.
- The app is intended for local demonstration on `127.0.0.1`.
- Private keys are generated without passwords for simplicity.
- The client and server must already know each other's public keys.
- The chat is turn-based.
- This is an educational demo, not a replacement for production TLS.
