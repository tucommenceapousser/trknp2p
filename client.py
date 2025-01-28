# client.py - Secure client with styled interactive CLI
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text

# Styled console for rich CLI output
console = Console()

# Load client's private key
def load_private_key(filepath: str):
    with open(filepath, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Securely connect to the server
def client():
    console.print(Panel("🌐 [bold blue]Initializing Secure Client...[/bold blue]", expand=False))

    # Load private key
    private_key = load_private_key("client_key")

    # Load server's public key
    with open("server_key.pub", "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(key_file.read())

    # Create client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(("127.0.0.1", 9999))
        console.print(Panel("[green]✅ Connected to Server![/green]", expand=False))
    except ConnectionError:
        console.print(Panel("[red]❌ Connection Failed![/red]", expand=False))
        return

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

    console.print(Panel("[bold cyan]🔒 Secure Communication Established[/bold cyan]", expand=False))

    # Styled interactive CLI for message exchange
    while True:
        message = Prompt.ask("[bold blue]You[/bold blue]", default="Type your message here")
        if message.lower() == "/exit":
            console.print("[yellow]🔔 Disconnecting...[/yellow]")
            break
        elif message.lower() == "/help":
            console.print("[bold magenta]Available Commands[/bold magenta]:\n/exit - Disconnect\n/help - Show commands")
            continue

        # Encrypt and send message
        encrypted_message = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
        client_socket.sendall(encrypted_message)

        console.print(f"[bold green]✔ Sent:[/bold green] {message}")

    client_socket.close()
    console.print("[bold yellow]🔌 Disconnected.[/bold yellow]")

if __name__ == "__main__":
    client()
