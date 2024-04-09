import os
import socket
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Decrypts data using the server's private key
def decrypt_rsa(encrypted_data, private_key):
    start_time = time.time()
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    decryption_time = (time.time() - start_time) * 1000
    print(f"Decryption time: {decryption_time} ms")
    return decrypted_data

def save_keys(private_key, public_key, private_key_filename, public_key_filename):
    # Save private key to file
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

def load_private_key(private_key_filename):
    with open(private_key_filename, "rb") as key_file:
        private_key_bytes = key_file.read()
        return serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())


def start_server(host='localhost', port=16000):
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, "secure/server_private_key.pem", "secure/server_public_key.pem")

    # Load existing private key
    private_key = load_private_key("secure/server_private_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")

                # Receive the client's public key
                client_public_key_pem = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    if data.startswith(b'-----BEGIN PUBLIC KEY-----'):
                        client_public_key_pem += data
                    else:
                        encrypted_message = data
                        break

                print("Client's public key received")

                # Print and decrypt the received message
                print("Encrypted message received:")
                if encrypted_message:
                    message = decrypt_rsa(encrypted_message, private_key)
                    print(f"Decrypted message: {message.decode('utf-8')}")

            print("SHUTTING DOWN SERVER AFTER THE CONNECTION.")

if __name__ == "__main__":
    start_server()