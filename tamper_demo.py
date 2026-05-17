from cryptography.exceptions import InvalidTag

from crypto_utils import decrypt_message, encrypt_message, generate_aes_key


def packet_preview(packet):
    """Return the first 64 hex characters of an encrypted packet."""
    return packet.hex()[:64] + "..."


def main():
    # 1. Generate a fresh AES-256 key.
    aes_key = generate_aes_key()

    # 2. Encrypt a plaintext message.
    plaintext = b"This message should stay private and unchanged."
    encrypted_packet = encrypt_message(aes_key, plaintext)

    print(f"Original plaintext: {plaintext.decode('utf-8')}")
    print(f"Encrypted packet preview: {packet_preview(encrypted_packet)}")

    # 3. Flip one byte in the encrypted packet to simulate tampering.
    tampered_packet = bytearray(encrypted_packet)
    tampered_packet[20] = tampered_packet[20] ^ 1
    tampered_packet = bytes(tampered_packet)

    print(f"Tampered packet preview: {packet_preview(tampered_packet)}")

    # 4-5. AES-GCM should reject the changed packet during decryption.
    try:
        decrypt_message(aes_key, tampered_packet)
        print("Decryption unexpectedly succeeded.")
    except InvalidTag:
        print("Decryption failed because message integrity check failed.")


if __name__ == "__main__":
    main()
