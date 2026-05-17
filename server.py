import os
import socket

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    decrypt_message,
    encrypt_message,
    load_private_key,
    load_public_key,
    recv_bytes,
    rsa_decrypt,
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


def chat_with_client(connection, aes_key):
    while True:
        try:
            # Receive and decrypt the client's encrypted chat message.
            encrypted_message = recv_bytes(connection)
            plaintext = decrypt_message(aes_key, encrypted_message)
        except InvalidTag:
            print("Message integrity check failed.")
            return
        except ConnectionError:
            print("Connection closed. Goodbye.")
            return

        message = plaintext.decode("utf-8")
        print(f"Client: {message}")

        if message == "exit":
            return

        # Ask the server user for a reply, then encrypt it before sending.
        reply = input("Server: ")
        encrypted_reply = encrypt_message(aes_key, reply.encode("utf-8"))
        print_encrypted_preview(encrypted_reply)
        send_bytes(connection, encrypted_reply)

        if reply == "exit":
            return


def handle_client(connection):
    # 1. Load the server's private key and the client's public key.
    server_private_key = load_private_key("keys/server_private.pem")
    client_public_key = load_public_key("keys/client_public.pem")

    # 4. Generate a fresh random nonce for client authentication.
    server_nonce = os.urandom(NONCE_SIZE)
    print("[1] Generated server nonce.")

    # 5. Send server_nonce to the client.
    send_bytes(connection, server_nonce)
    print("[2] Sent server nonce challenge to client.")

    # 6. Receive client_signature.
    client_signature = recv_bytes(connection)
    print("[3] Received client signature.")

    # 7. Verify that the client signed server_nonce correctly.
    if not verify_signature(client_public_key, server_nonce, client_signature):
        # 8. If verification fails, print an error and close the connection.
        print("Error: client authentication failed.")
        return None
    print("[4] Verified client signature successfully.")

    # 9. Receive client_nonce.
    client_nonce = recv_bytes(connection)
    print("[5] Received client nonce challenge.")

    # 10. Sign client_nonce using server_private_key.
    server_signature = sign_message(server_private_key, client_nonce)
    print("[6] Signed client nonce.")

    # 11. Send server_signature.
    send_bytes(connection, server_signature)
    print("[7] Sent server signature to client.")

    # 12. Receive encrypted_aes_key.
    encrypted_aes_key = recv_bytes(connection)
    print("[8] Received encrypted AES session key.")

    # 13. Decrypt encrypted_aes_key using server_private_key.
    aes_key = rsa_decrypt(server_private_key, encrypted_aes_key)
    print("[9] Decrypted AES session key.")

    # Keep this simple for now; the chat loop will use aes_key later.
    if len(aes_key) != 32:
        print("Error: received AES key has the wrong length.")
        return None

    # 14-16. Print handshake success messages.
    print("Client authenticated successfully.")
    print("Server authentication completed.")
    print("[10] Secure session established.")
    return aes_key


def main():
    try:
        # 2. Listen on 127.0.0.1:5000.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(1)
            print(f"Server listening on {HOST}:{PORT}...")

            # 3. Accept one client connection.
            connection, address = server_socket.accept()
            with connection:
                print(f"Client connected from {address}.")
                aes_key = handle_client(connection)
                if aes_key is not None:
                    chat_with_client(connection, aes_key)

    except ConnectionError as error:
        print(f"Connection error: {error}")
    except OSError as error:
        print(f"Socket error: {error}")
    except Exception as error:
        print(f"Authentication or crypto error: {error}")


if __name__ == "__main__":
    main()
