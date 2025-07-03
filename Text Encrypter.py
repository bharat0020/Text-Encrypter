import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_key(password: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        ).derive(password.encode())
    )

def encrypt(message: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    return salt + Fernet(key).encrypt(message.encode())

def decrypt(encrypted_data: bytes, password: str) -> str:
    salt, token = encrypted_data[:16], encrypted_data[16:]
    try:
        key = generate_key(password, salt)
        return Fernet(key).decrypt(token).decode()
    except:
        return "❌ Incorrect password or corrupted data."



# === USAGE ===
message = input("Enter message to encrypt: ")
password = input("Set password: ")

encrypted = encrypt(message, password)
print("\n🔒 Encrypted (save securely):\n", encrypted)

if input("\nDecrypt now? (yes/no): ").lower() == "yes":
    pwd = input("Enter password to decrypt: ")
    print("\n🔓 Decrypted:", decrypt(encrypted, pwd))
