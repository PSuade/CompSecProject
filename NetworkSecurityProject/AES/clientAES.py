import socket
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import secrets
import struct


# Generates a random AES key and IV
def generate_aes_keys():
    aes_key = secrets.token_bytes(16)  # Using AES-128
    aes_iv = secrets.token_bytes(16)   
    return aes_key, aes_iv

# Saves AES key and IV to files in the secure folder
def save_aes_key_iv(aes_key, aes_iv):

    # Save AES key to file
    with open("secure/client_aes_key.pem", "wb") as key_file:
        key_file.write(aes_key)

    # Save IV to file
    with open("secure/client_aes_iv.pem", "wb") as iv_file:
        iv_file.write(aes_iv)

# AES Encryption with performance measurement
def encrypt_aes(data, key, iv):
    start_time = time.time()  # Start timing
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    end_time = time.time()  # End timing
    encryption_time = (end_time - start_time) * 1000
    print(f"Encryption time: {encryption_time} milliseconds")  # Print time in milliseconds
    return ct


# Client Main Function
def connect_to_server(message, host='localhost', port=14000):
    # Generates AES key and IV
    aes_key, aes_iv = generate_aes_keys()

    # Saves both to files
    save_aes_key_iv(aes_key, aes_iv)

    print("Connecting with server...")
    input("Press Enter to continue...")
    
    #Initializes connection with server
    with socket.create_connection((host, port)) as sock:
        with ssl.wrap_socket(sock) as ssock:
            print("Connected. Encrypting message...")
            input("Press Enter to continue...")
            
            # Sends AES key length to server
            key_length_bytes = struct.pack('>I', len(aes_key))
            ssock.sendall(key_length_bytes)
            print(f"AES key length sent to server: {len(aes_key)}")

            # Sends AES key to server
            ssock.sendall(aes_key)
            print("AES key sent to server:")

            # Sends AES IV length to server
            iv_length_bytes = struct.pack('>I', len(aes_iv))
            ssock.sendall(iv_length_bytes)
            print(f"AES IV length sent to server: {len(aes_iv)}")

            # Sends AES IV to server
            ssock.sendall(aes_iv)
            print("AES IV sent to server:")

            print("Message encrypted. Sending to server...")
            input("Press Enter to continue...")

            # Encrypts message with AES
            encrypted_message = encrypt_aes(message.encode('utf-8'), aes_key, aes_iv)


            # Sends encrypted message to server
            ssock.sendall(encrypted_message)
            print("Encrypted message sent to the server")

if __name__ == "__main__":
    try:
        with open("file.txt", "r") as file:
            content = file.read()

    except Exception as e:
        print(f"An error has occurred: {e}")
        content = "Default message"  # Fallback message in case of an error

    # Connects to server and sends contents of file.txt
    connect_to_server(content)