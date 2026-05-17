import os
import socket
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
LENGTH_PREFIX_SIZE = 4


def load_private_key(path):
    """Load an RSA private key from a PEM file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def load_public_key(path):
    """Load an RSA public key from a PEM file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def sign_message(private_key, message):
    """Sign bytes using RSA-PSS and SHA-256."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, message, signature):
    """Return True only when the RSA-PSS signature is valid."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(public_key, plaintext):
    """Encrypt bytes using RSA-OAEP and SHA-256."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext):
    """Decrypt bytes using RSA-OAEP and SHA-256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_aes_key():
    """Create a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(aes_key, plaintext):
    """Encrypt bytes with AES-256-GCM.

    The returned bytes are nonce + ciphertext_and_tag, so the receiver has
    everything needed to decrypt with the same AES key.
    """
    nonce = os.urandom(GCM_NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext


def decrypt_message(aes_key, encrypted_message):
    """Decrypt bytes that were produced by encrypt_message."""
    nonce = encrypted_message[:GCM_NONCE_SIZE]
    ciphertext = encrypted_message[GCM_NONCE_SIZE:]

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def send_bytes(sock, data):
    """Send bytes with a 4-byte big-endian length prefix."""
    length_prefix = struct.pack("!I", len(data))
    sock.sendall(length_prefix + data)


def recv_exactly(sock, num_bytes):
    """Keep receiving until exactly num_bytes have arrived."""
    chunks = []
    bytes_received = 0

    while bytes_received < num_bytes:
        chunk = sock.recv(num_bytes - bytes_received)
        if chunk == b"":
            raise ConnectionError("Socket connection closed unexpectedly.")
        chunks.append(chunk)
        bytes_received += len(chunk)

    return b"".join(chunks)


def recv_bytes(sock):
    """Receive bytes sent by send_bytes."""
    length_prefix = recv_exactly(sock, LENGTH_PREFIX_SIZE)
    message_length = struct.unpack("!I", length_prefix)[0]
    return recv_exactly(sock, message_length)
