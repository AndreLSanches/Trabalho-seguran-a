import os
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password: str) -> bytes:
    """Gera uma chave baseada em uma senha usando SHA-256."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_file(file_path: str, key: bytes) -> None:
    """Encripta um arquivo usando a chave fornecida."""
    with open(file_path, 'rb') as file:
        data = file.read()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    
    with open(file_path, 'wb') as file:
        file.write(encrypted)

def decrypt_file(file_path: str, key: bytes) -> None:
    """Decripta um arquivo usando a chave fornecida."""
    with open(file_path, 'rb') as file:
        data = file.read()
    
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    
    with open(file_path, 'wb') as file:
        file.write(decrypted)

if __name__ == "__main__":
    username = input("Digite seu nome de usuário: ")
    password = input("Digite uma senha para proteger suas chaves: ")
    file_path = f"{username}_keys.txt"
    
    key = generate_key(password)
    
    if not os.path.exists(file_path):
        print(f"Arquivo {file_path} não encontrado.")
        exit()
    
    encrypt_file(file_path, key)
    print(f"Chaves do usuário {username} foram armazenadas e criptografadas com sucesso.")
