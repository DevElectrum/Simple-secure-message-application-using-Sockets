# Design Document

## Project Overview

This project is a terminal-based secure messaging application built with Python sockets. It contains a client and server that connect over localhost, authenticate each other, establish a shared AES session key, and exchange encrypted messages.

The design is intentionally small and course-focused. It demonstrates the core Network Security goals without adding production features such as certificates, multiple clients, or asynchronous messaging.

## Security Goals

### Mutual Authentication

The client and server each prove their identity by signing a random challenge nonce. The server verifies the client's signature using the client's public key, and the client verifies the server's signature using the server's public key.

### Confidentiality

The client generates a fresh AES-256 session key and encrypts it with the server's RSA public key using RSA-OAEP. After that, chat messages are encrypted with AES-256-GCM so plaintext is not sent over the socket.

### Message Integrity

AES-GCM provides an authentication tag for each encrypted message. If an encrypted packet is changed in transit, decryption fails and the program reports an integrity-check failure.

## High-Level Protocol Diagram

```text
Client                                Server
  | -------- TCP connect -------------> |
  | <------- server nonce ------------- |
  | ---- sign(server nonce) ----------> |
  | ---- client nonce ----------------> |
  | <--- sign(client nonce) ----------- |
  | ---- RSA-OAEP(AES key) -----------> |
  | ===== AES-GCM encrypted chat ===== |
```

## Low-Level Cryptographic Flow Diagram

```text
1. Server creates server_nonce
2. Client signs server_nonce with client_private.pem
3. Server verifies signature with client_public.pem

4. Client creates client_nonce
5. Server signs client_nonce with server_private.pem
6. Client verifies signature with server_public.pem

7. Client creates random 32-byte AES session key
8. Client encrypts AES key with server_public.pem using RSA-OAEP
9. Server decrypts AES key with server_private.pem

10. Each chat message:
    plaintext
      -> AES-256-GCM encrypt with random 12-byte nonce
      -> packet = nonce || ciphertext || authentication tag
      -> 4-byte length prefix + packet over TCP socket
```

## Step-by-Step Protocol Explanation

1. The server starts listening on `127.0.0.1:5000`.
2. The client opens a TCP socket connection to the server.
3. The server generates a random 32-byte nonce and sends it to the client.
4. The client signs the server nonce with `client_private.pem` using RSA-PSS and SHA-256.
5. The client sends the signature to the server.
6. The server verifies the signature with `client_public.pem`.
7. The client generates a random 32-byte nonce and sends it to the server.
8. The server signs the client nonce with `server_private.pem` using RSA-PSS and SHA-256.
9. The server sends the signature to the client.
10. The client verifies the signature with `server_public.pem`.
11. The client generates a random 256-bit AES session key.
12. The client encrypts the AES key with `server_public.pem` using RSA-OAEP and SHA-256.
13. The server decrypts the AES key with `server_private.pem`.
14. The client and server exchange chat messages encrypted with AES-256-GCM.
15. Messages are sent with a 4-byte big-endian length prefix so the receiver knows how many bytes to read.

## Cryptographic Choices

- RSA-PSS for signatures/authentication: used to prove ownership of each side's private key while signing unpredictable nonce challenges.
- RSA-OAEP for AES session key encryption: used so only the server private key can recover the client-generated AES key.
- AES-256-GCM for encrypted authenticated messages: provides confidentiality and integrity for each chat message.
- 4-byte length-prefix framing for sockets: prevents partial TCP reads from breaking message boundaries.

## Working Application Summary

The working application includes:

- `generate_keys.py` for local RSA key generation
- `server.py` for the listening server
- `client.py` for the connecting client
- `crypto_utils.py` for shared cryptographic and socket helper functions
- `tamper_demo.py` for demonstrating integrity failure when ciphertext is modified
- `DEMO_TRANSCRIPT.md` for sample evidence of successful execution

## Limitations / Future Work

- Only one client is supported.
- The app runs as a local demo on `127.0.0.1`.
- Private keys are not password-protected.
- There is no certificate authority or PKI.
- Public keys must be distributed before running the app.
- Chat is turn-based.
- Future work could add multiple clients, password-protected keys, certificates, logging, and a more complete user interface.
