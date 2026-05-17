# Demo Transcript

This transcript shows a sample run of the stable secure message application.

## 1. Key Generation

Command:

```bash
python generate_keys.py
```

Sample output:

```text
Generated RSA keys in the keys/ folder.
```

## 2. Server Start

Command:

```bash
python server.py
```

Sample output:

```text
Server listening on 127.0.0.1:5000...
Client connected from ('127.0.0.1', 57902).
```

## 3. Client Start

Command:

```bash
python client.py
```

The client connects to the server over a local TCP socket.

## 4. Successful Mutual Authentication

Server output:

```text
[1] Generated server nonce.
[2] Sent server nonce challenge to client.
[3] Received client signature.
[4] Verified client signature successfully.
[5] Received client nonce challenge.
[6] Signed client nonce.
[7] Sent server signature to client.
[8] Received encrypted AES session key.
[9] Decrypted AES session key.
Client authenticated successfully.
Server authentication completed.
[10] Secure session established.
```

Client output:

```text
[1] Received server nonce challenge.
[2] Signed server nonce.
[3] Sent client signature.
[4] Generated client nonce challenge.
[5] Sent client nonce to server.
[6] Received server signature.
[7] Verified server signature successfully.
[8] Generated AES-256 session key.
[9] Encrypted AES session key with server public key.
Server authenticated successfully.
[10] Secure session established.
```

## 5. Encrypted Message Exchange

Client output:

```text
Client: hello secure server
Encrypted packet preview: 4cc46564f67442da5a6b72d0673d10c914e9fec993a5e4368f3145126e290d9b...
Server: hello secure client
Client: exit
Encrypted packet preview: 160424655cd1ebf960030649dc5b1c79773f6e0f16b122ecad0c83da95be2090...
```

Server output:

```text
Client: hello secure server
Server: hello secure client
Encrypted packet preview: 43c28ff5f3f9264224ead977d07f76f357574da88fc9899b5c132a90a9b5edd0...
Client: exit
```

The encrypted packet previews show ciphertext rather than plaintext moving across the socket.

## 6. Tamper / Integrity Failure Demo

Command:

```bash
python tamper_demo.py
```

Sample output:

```text
Original plaintext: This message should stay private and unchanged.
Encrypted packet preview: 96382953bc4df74355da27a042021d28c233fef4a1032ef4ed284ef6d4ade5bd...
Tampered packet preview: 96382953bc4df74355da27a042021d28c233fef4a0032ef4ed284ef6d4ade5bd...
Decryption failed because message integrity check failed.
```
