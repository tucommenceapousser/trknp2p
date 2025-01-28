# keygen.py - Generate RSA key pairs for client and server
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(filepath: str):
    # Generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    # Save private key
    with open(filepath, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Save public key
    public_key = private_key.public_key()
    with open(filepath + ".pub", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"Keys generated and saved at {filepath} and {filepath}.pub")

# Generate keys for server and client
generate_keypair("server_key")
generate_keypair("client_key")
