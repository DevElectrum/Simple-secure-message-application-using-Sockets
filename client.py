import os
import socket

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    decrypt_message,
    encrypt_message,
    generate_aes_key,
    load_private_key,
    load_public_key,
    recv_bytes,
    rsa_encrypt,
    send_bytes,
    sign_message,
    verify_signature,
)


HOST = "127.0.0.1"
PORT = 5000
NONCE_SIZE = 32


def print_encrypted_preview(encrypted_packet):
    # Show a small preview so we can see ciphertext is not readable plaintext.
    print(f"Encrypted packet preview: {encrypted_packet.hex()[:64]}...")


def chat_with_server(client_socket, aes_key):
    while True:
        # Ask the client user for a message, then encrypt it before sending.
        message = input("Client: ")
        encrypted_message = encrypt_message(aes_key, message.encode("utf-8"))
        print_encrypted_preview(encrypted_message)
        send_bytes(client_socket, encrypted_message)

        if message == "exit":
            return

        try:
            # Receive and decrypt the server's encrypted reply.
            encrypted_reply = recv_bytes(client_socket)
            plaintext = decrypt_message(aes_key, encrypted_reply)
        except InvalidTag:
            print("Message integrity check failed.")
            return
        except ConnectionError:
            print("Connection closed. Goodbye.")
            return

        reply = plaintext.decode("utf-8")
        print(f"Server: {reply}")

        if reply == "exit":
            return


def run_handshake(client_socket):
    # 1. Load the client's private key and the server's public key.
    client_private_key = load_private_key("keys/client_private.pem")
    server_public_key = load_public_key("keys/server_public.pem")

    # 3. Receive server_nonce.
    server_nonce = recv_bytes(client_socket)
    print("[1] Received server nonce challenge.")

    # 4. Sign server_nonce using client_private_key.
    client_signature = sign_message(client_private_key, server_nonce)
    print("[2] Signed server nonce.")

    # 5. Send client_signature.
    send_bytes(client_socket, client_signature)
    print("[3] Sent client signature.")

    # 6. Generate a fresh random nonce for server authentication.
    client_nonce = os.urandom(NONCE_SIZE)
    print("[4] Generated client nonce challenge.")

    # 7. Send client_nonce.
    send_bytes(client_socket, client_nonce)
    print("[5] Sent client nonce to server.")

    # 8. Receive server_signature.
    server_signature = recv_bytes(client_socket)
    print("[6] Received server signature.")

    # 9. Verify that the server signed client_nonce correctly.
    if not verify_signature(server_public_key, client_nonce, server_signature):
        # 10. If verification fails, print an error and close the connection.
        print("Error: server authentication failed.")
        return None
    print("[7] Verified server signature successfully.")

    # 11. Generate a 256-bit AES key.
    aes_key = generate_aes_key()
    print("[8] Generated AES-256 session key.")

    # 12. Encrypt the AES key using server_public_key.
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)
    print("[9] Encrypted AES session key with server public key.")

    # 13. Send encrypted_aes_key.
    send_bytes(client_socket, encrypted_aes_key)

    # 14-15. Print handshake success messages.
    print("Server authenticated successfully.")
    print("[10] Secure session established.")
    return aes_key


def main():
    try:
        # 2. Connect to 127.0.0.1:5000.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            aes_key = run_handshake(client_socket)
            if aes_key is not None:
                chat_with_server(client_socket, aes_key)

    except ConnectionError as error:
        print(f"Connection error: {error}")
    except OSError as error:
        print(f"Socket error: {error}")
    except Exception as error:
        print(f"Authentication or crypto error: {error}")


if __name__ == "__main__":
    main()
