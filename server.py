from socket import AF_INET, SOCK_STREAM, socket
from merged_code import sha256_hash, sha256_verify, get_random_primos, decrypt, generate_keys, generate_psk, get_value_to_send
import sys
import platform
import ctypes
import threading

# Configurações do servidor do professor
# HOST = "200.145.184.166"
# SERVER_PORT = 40665
# BUFFER_SIZE = 1048576

# Para testar o funcionamento na máquina local
HOST = "localhost"
SERVER_PORT = 4129
BUFFER_SIZE = 1048576

DH_P = None
PRIVATE_VALUE = None
RSA_PRIVATE_KEY = None

clients = []
clients_lock = threading.Lock()

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

def get_to_send(client: socket) -> None:
    global PRIVATE_VALUE
    global DH_P

    print("Preparando valor que será enviado")
    alpha, DH_P = [get_random_primos() for i in range(2)]
    PRIVATE_VALUE, to_send = get_value_to_send(alpha, DH_P)
    print("Valor que será enviado foi produzido")
    
    response = "%d:%d:%d" % (alpha, DH_P, to_send)
    client.send(response.encode('utf-8'))

def get_rsa_public_key(client: socket, client_value: int) -> None:
    global RSA_PRIVATE_KEY

    print("Gerando PSK")
    psk = generate_psk(client_value, PRIVATE_VALUE, DH_P)
    print("Gerando chaves RSA")
    puk, RSA_PRIVATE_KEY = generate_keys()
    print("Chaves RSA foram geradas")
    
    response = "%s:%s:%s" % (str(puk[0] * psk), str(puk[1] * psk), sha256_hash(str(psk)))
    client.send(response.encode('utf-8'))

def message_exchange(client: socket, msg_encrypted: str) -> None:
    print("A mensagem encriptada foi recebida do cliente")
    message = decrypt(msg_encrypted, RSA_PRIVATE_KEY)
    print("Mensagem decriptada: \033[1;32m%s\033[0m" % message)
    
    client.send("Mensagem foi recebida com sucesso e decriptada no servidor".encode("utf-8"))

def select_service(client: socket, service: str | None, value: int | str | None, error_msg: str = "Nenhum serviço encontrado") -> None:
    match service:
        case "get_server_value": get_to_send(client)
        case "get_rsa_public_key":
            if PRIVATE_VALUE == None: select_service(client, None, value, "Pre-Shared Key ainda não foi gerada")
            get_rsa_public_key(client, int(value))
        case "message_exchange":
            if RSA_PRIVATE_KEY == None: select_service(client, None, value, "Chave RSA ainda não foi gerada")
            message_exchange(client, value)
        case _: client.send(("!"+error_msg).encode('utf-8'))

def handle_client(client: socket):
    while True:
        try:
            msg = str(client.recv(BUFFER_SIZE).decode('utf-8'))
            if not msg:
                break
            splitted = msg.split(":")
            service, value = str(splitted[0]), (splitted[1] if len(splitted) > 1 else None)
            select_service(client, service, value)
        except Exception as e:
            print(f"Erro ao lidar com cliente: {e}")
            break
    with clients_lock:
        clients.remove(client)
    client.close()
    print("Cliente desconectado")

if __name__ == "__main__":
    enable_terminal_color()
    print("\n\033[1;37m --- Servidor --- \033[0m\n")
    
    server = socket(AF_INET, SOCK_STREAM)
    server.bind((HOST, SERVER_PORT))
    server.listen(10)

    while True:
        client, _ = server.accept()
        with clients_lock:
            clients.append(client)
        thread = threading.Thread(target=handle_client, args=[client])
        thread.start()