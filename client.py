# client.py - Secure client for encrypted communication
import socket
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Load client's private key
def load_private_key(filepath: str):
    with open(filepath, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Securely connect to server
def client():
    # Load private key
    private_key = load_private_key("client_key")

    # Load server's public key
    with open("server_key.pub", "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(key_file.read())

    # Create client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 9999))

    # Send public key to server
    with open("client_key.pub", "rb") as pub_file:
        client_socket.sendall(pub_file.read())

    # Receive encrypted session key
    encrypted_session_key = client_socket.recv(4096)

    # Decrypt session key with private key
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Receive nonce
    nonce = client_socket.recv(12)
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    print("Secure communication established. Type your messages:")
    while True:
        message = input("You: ")
        if message.lower() == "exit":
            break
        # Encrypt and send message
        encrypted_message = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
        client_socket.sendall(encrypted_message)

    client_socket.close()

if __name__ == "__main__":
    client()
