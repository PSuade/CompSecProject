import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time
import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(data, public_key):
    start_time = time.time()
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encryption_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    print(f"Encryption time: {encryption_time} milliseconds")
    return encrypted_data

def save_keys(private_key, public_key, private_key_filename, public_key_filename):
    # Saves private key to file
    with open(private_key_filename, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to file
    with open(public_key_filename, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key_bytes = key_file.read()
        return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

#Main client function
def connect_to_server(content, host='localhost', port=16000):
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, "secure/client_private_key.pem", "secure/client_public_key.pem")

    print("Connecting with server...")
    input("Press Enter to continue...")

    #create connection with server
    with socket.create_connection((host, port)) as sock:
        sock.sendall(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        print("Connected. Encrypting message...")
        input("Press Enter to continue...")

        #Loads server public key, encrypts message and sends it to server
        server_public_key = load_public_key("secure/server_public_key.pem")
        encrypted_message = encrypt_rsa(content.encode('utf-8'), server_public_key)

        print("Message encrypted. Sending to server...")
        input("Press Enter to continue...")

        sock.sendall(encrypted_message)


if __name__ == "__main__":
    file_size = os.path.getsize("file.txt")

    try:
        with open("file.txt", "r") as file:
            content = file.read()
    except Exception as e:
        print(f"An error has occurred: {e}")
        content = "Default message"  # Fallback message in case of an error

    # Connect to server on a single port
    connect_to_server(content=content, port=16000)