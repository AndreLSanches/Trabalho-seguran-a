from socket import AF_INET, SOCK_STREAM, socket
from merged_code import sha256_hash, sha256_verify, get_random_primos, decrypt, generate_keys, encrypt, generate_psk, get_value_to_send
import sys
import platform
import threading
import ctypes

# Configurações do servidor do professor
# HOST = "200.145.184.166"
# SERVER_PORT = 40665
# BUFFER_SIZE = 1048576

# Para testar o funcionamento na máquina local
HOST = "localhost"
SERVER_PORT = 4129
BUFFER_SIZE = 1048576

# Lista para armazenar os sockets dos clientes conectados
clients = []

def enable_terminal_color():
    if not sys.stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    else:
        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32

def make_request(client, request):
    try:
        client.send(request.encode("utf-8"))
        response = client.recv(BUFFER_SIZE).decode("utf-8")

        if len(response) == 0 or response[0] == "!":
            print(response[1:])
            exit()
        
        return response
    except Exception as e:
        print(f"Erro ao fazer requisição: {e}")
        client.close()
        exit()

def handle_client(client):
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            print(f"Mensagem recebida: {message}")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            clients.remove(client)
            client.close()
            break

if __name__ == "__main__":
    enable_terminal_color()
    print("\n --- Cliente --- \n")

    username = input("Digite seu nome de usuário: ")

    client = socket(AF_INET, SOCK_STREAM)
    try:
        client.connect((HOST, SERVER_PORT))
    except Exception as e:
        print(f"Erro ao conectar ao servidor: {e}")
        exit()

    request = "get_server_value"
    response = make_request(client, request)
    alpha, p, server_value = [int(num) for num in response.split(":")]

    private, to_send = get_value_to_send(alpha, p)
    psk = generate_psk(server_value, private, p)
    print("PSK gerada")

    request = "get_rsa_public_key:%d" % to_send
    response = make_request(client, request)
    print("A chave pública encriptada foi recebida")

    e_encrypted, n_encrypted, checksum = response.split(":")
    
    if not sha256_hash(str(psk)) == checksum:
        print("Valor de verificação não confere com a Pre-Shared Key")
        exit()
    
    e, n = int(e_encrypted) // psk, int(n_encrypted) // psk
    puk = (e, n)
    print("A chave pública foi decriptada")

    private_key = generate_keys()[1]  # Gerar chave privada local

    with open(f"{username}_keys.txt", "w") as f:
        f.write(f"Usuário: {username}\n")
        f.write(f"Chave Pública: {puk}\n")
        f.write(f"Chave Privada: {private_key}\n")

    def receive_messages(client_socket):
        while True:
            try:
                msg = client_socket.recv(2048).decode('utf-8')
                if msg:
                    print(f"\033[1;33m{msg}\033[0m")
            except Exception as e:
                print(f"Erro ao receber mensagem: {e}")
                client_socket.close()
                break

    def send_messages(client_socket):
        while True:
            try:
                message = input("\033[1;32mDigite a mensagem que será enviada ao servidor: \033[0m")
                if message:
                    encrypted_message = encrypt(f'<{username}> {message}', puk)
                    request = f"message_exchange:{encrypted_message}"
                    client_socket.send(request.encode('utf-8'))

                    with open(f"{username}_messages.txt", "a") as f:
                        f.write(f"Mensagem Enviada: {message}\n")
                        f.write(f"Mensagem Encriptada: {request.split(':')[1]}\n")
            except Exception as e:
                print(f"Erro ao enviar mensagem: {e}")
                client_socket.close()
                break

    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()

    while True:
        pass
    
    client.close()
