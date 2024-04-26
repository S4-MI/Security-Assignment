import os
import socket
import threading

from AES import encrypt, key_expansion, decrypt
from RSA import generate_keypair, encrypt as rsa_encrypt, decrypt as rsa_decrypt

AES_KEY = 'Thats my Kung Fu'


def read_key():
    with open('Don’t Open This/private_key.txt', 'r') as file:
        private_key = file.read()
        return eval(private_key)


def write_key(private_key):
    if not os.path.exists('Don’t Open This'):
        os.makedirs('Don’t Open This')

    with open('Don’t Open This/private_key.txt', 'w') as file:
        file.write(str(private_key))


def generate_write_and_get_key():
    key_result = generate_keypair(16)
    public_key, private_key = key_result['keys']
    # print("\nPublic Key: (e, n) =", public_key)
    # print("Private key: (d, n) =", private_key)

    write_key(private_key)
    return public_key


def encrypt_message(message: str, key: str):
    keys = key_expansion(key)['keys']
    encrypted_message = encrypt(text=message, keys=keys)['cipher_text']
    return encrypted_message


def encrypt_key(key: str):
    public_key = generate_write_and_get_key()
    encrypted_key = rsa_encrypt(plaintext=key, public_key=public_key)['cipher_text']
    return f'{encrypted_key}'


def decrypt_key(encrypted_key: str):
    private_key = read_key()
    decrypted_key = rsa_decrypt(ciphertext=encrypted_key, private_key=private_key)['plain_text']
    return decrypted_key


def decrypt_message(encrypted_message: str, key: str):
    keys = key_expansion(key)['keys']
    decrypted_message = decrypt(cipher_text=encrypted_message, keys=keys)['text']
    return decrypted_message


def handle_client(client1, client2):
    client1_socket, client1_address = client1
    client2_socket, client2_address = client2

    print('in handle client')

    try:
        client1_socket.sendall(b'1')
        client2_socket.sendall(b'2')
    except ConnectionResetError:
        print('Connection Error')
        client1_socket.close()
        client2_socket.close()
        return

    turn = 1

    while True:
        try:
            if turn:
                data = client1_socket.recv(1024)
                if not data:
                    print('Connection Error in 1st message')
                    break
                message = data.decode()
                print(f'Message from 1st user {message}')
                client2_socket.sendall(data)

                data = client1_socket.recv(1024)
                if not data:
                    print('Connection Error in 2nd message')
                    break
                message = data.decode()
                print(f'Message from 1st user {message}')
                client2_socket.sendall(data)
                print('\n')
                turn = 0

            else:
                data = client2_socket.recv(1024)
                if not data:
                    print('Connection Error 1st message')
                    break
                message = data.decode()

                print(f'Message from 2nd user {message}')
                client1_socket.sendall(data)

                data = client2_socket.recv(1024)
                if not data:
                    print('Connection Error 2nd message')
                    break

                message = data.decode()

                print(f'Message from 2nd user {message}')
                client1_socket.sendall(data)

                print('\n')
                turn = 1

        except ConnectionResetError:
            print('Connection Error')
            break

    client1_socket.close()
    client2_socket.close()


def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    clients = []

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        clients.append((client_socket, client_address))

        if len(clients) % 2 == 0:
            client_handler = threading.Thread(
                target=handle_client,
                args=(clients[-2], clients[-1])
            )
            client_handler.start()


def handle_get_message(client_socket):
    print('waiting for message...')
    data1 = client_socket.recv(1024)

    if not data1:
        print('Connection Error on get message, 1st message')
        return False

    data2 = client_socket.recv(1024)
    if not data2:
        print('Connection Error on get message, 2nd message')
        return False

    cipher_text = data1.decode()
    encrypted_key = eval(data2.decode())

    key = decrypt_key(encrypted_key)
    message = decrypt_message(encrypted_message=cipher_text, key=key)
    print(f"Message : {message}\n")

    return True


def handle_send_message(client_socket, message: str):
    key = AES_KEY
    encrypted_message = encrypt_message(message=message, key=key)
    encrypted_key = encrypt_key(key=key)

    try:
        client_socket.sendall(encrypted_message.encode())
        print('Message sent')
        client_socket.sendall(encrypted_key.encode())
        print('Key sent')
    except ConnectionResetError:
        print('Connection Error')
        return False

    return True


def start_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server on {host}:{port}")

    data = client_socket.recv(1024)
    response = data.decode()
    print(f"Received from server: {response}")

    if str(response).lower().strip() == '1':
        message = input("Enter message: ")
        response = handle_send_message(client_socket, message=message)
        if not response:
            client_socket.close()
            return

    while True:
        try:
            response = handle_get_message(client_socket)
            if not response:
                break
            message = input("Enter message: ")
            response = handle_send_message(client_socket, message=message)
            if not response:
                break
        except ConnectionResetError:
            print('Connection Error on send message')
            break

    client_socket.close()


def main():
    mode = input("Choose mode - 'server' or 'client': ").lower()

    if mode == "s":
        host = '127.0.0.1'
        port = 9000
        start_server(host, port)
    elif mode == "c":
        host = '127.0.0.1'
        port = 9000
        start_client(host, port)
    else:
        print("Invalid mode. Choose 'server' or 'client'.")


def test():
    key = AES_KEY
    encrypted_message = encrypt_message(message='Two One Nine Two', key=key)
    encrypted_key = encrypt_key(key=key)

    print(f"Encrypted Message: {encrypted_message}")
    print(f"Encrypted Key: {encrypted_key}")

    cipher_text = encrypted_message
    encrypted_key = eval(encrypted_key)

    key = decrypt_key(encrypted_key)
    message = decrypt_message(encrypted_message=cipher_text, key=key)

    print(f"Decrypted Message: {message}")


if __name__ == "__main__":
    # test()
    main()
