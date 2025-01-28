# server.py - Secure server for encrypted communication
import socket
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from os import urandom

# Load server's private key
def load_private_key(filepath: str):
    with open(filepath, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Securely exchange keys and communicate
def server():
    # Load private key
    private_key = load_private_key("server_key")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 9999))
    server_socket.listen(1)
    print("Server listening on port 9999...")

    # Accept client connection
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    # Receive client's public key
    client_public_key = serialization.load_pem_public_key(conn.recv(4096))

    # Generate AES session key
    session_key = urandom(32)

    # Encrypt session key with client's public key
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Send encrypted session key to client
    conn.sendall(encrypted_session_key)

    # Start encrypted communication
    nonce = urandom(12)  # Random nonce for AES-GCM
    conn.sendall(nonce)  # Send nonce to client
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))

    print("Secure communication established. Waiting for messages...")
    decryptor = cipher.decryptor()
    while True:
        encrypted_message = conn.recv(4096)
        if not encrypted_message:
            break
        # Decrypt the message
        plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
        print(f"Client: {plaintext.decode('utf-8')}")
    conn.close()

if __name__ == "__main__":
    server()
