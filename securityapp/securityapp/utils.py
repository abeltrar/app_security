import secrets
from cryptography.fernet import Fernet

def generate_token():
    return secrets.token_urlsafe(32)



def load_key():
    # Leer la clave desde el archivo
    with open('secret.key', 'rb') as key_file:
        return key_file.read()

# Cargar la clave y crear el objeto Fernet
key = load_key()
cipher_suite = Fernet(key)

def encrypt_token(token):
    return cipher_suite.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token):
   
    try:
        decrypted_token = cipher_suite.decrypt(encrypted_token.encode()).decode()
        return decrypted_token
    except Exception as e:
        print(f"Error decrypting token: {str(e)}")
        raise

