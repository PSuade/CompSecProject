import socket
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time


def decrypt_aes(ct, key, iv):
    start_time = time.time()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ct) + decryptor.finalize()
    end_time = time.time()
    decryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
    print(f"Decryption time: {decryption_time} milliseconds")
    return decrypted_data.decode('utf-8', errors='ignore')

#Server Main Function
def start_server(host='localhost', port=14000):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="secure/server.pem", keyfile="secure/server.key")  

    # Initializes server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = s.accept()  # Accepts a single connection
        with context.wrap_socket(conn, server_side=True) as ssock:
            print(f"Connected by {addr}")

            # Receives AES key length from client
            key_length = int.from_bytes(ssock.recv(4), byteorder='big')
            print(f"AES key length received from client: {key_length}")

            # Receives AES key from client
            aes_key = b''
            while len(aes_key) < key_length:
                aes_key += ssock.recv(key_length - len(aes_key))
            print("AES key received from client:")

            # Receives AES IV length from client
            iv_length = int.from_bytes(ssock.recv(4), byteorder='big')
            print(f"AES IV length received from client: {iv_length}")

            # Receives AES IV from client
            aes_iv = b''
            while len(aes_iv) < iv_length:
                aes_iv += ssock.recv(iv_length - len(aes_iv))
            print("AES IV received from client:")

            # Initializes buffer to accumulate received data
            encrypted_message = b''
            while True:
                part = ssock.recv(4096)  # Receive up to 4096 bytes
                if not part:
                    break  # Exits loop if there's no more data
                encrypted_message += part

            print("Encrypted message received from client")

            # Decrypt and process the message if any data was received
            if encrypted_message:
                message = decrypt_aes(encrypted_message, aes_key, aes_iv)
                print(f"Decrypted message: {message}")
            else:
                print("No encrypted message received")

        print("SHUTTING DOWN SERVER AFTER THE CONNECTION.")

if __name__ == "__main__":
    start_server()









