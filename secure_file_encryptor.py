import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import getpass

# Derive a Fernet key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + encrypted)
    print(f"🔒 File encrypted and saved as {file_path}.enc")

# Decrypt file
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        content = f.read()
    salt = content[:16]
    encrypted_data = content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted_data)
    except:
        print("❌ Incorrect password or corrupted file.")
        return

    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    print(f"✅ File decrypted and saved as {output_path}")

# Menu
def main():
    print("\n🔐 Secure File Encryptor Tool")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Select (1/2): ")

    file_path = input("Enter file path: ")
    if not os.path.isfile(file_path):
        print("❌ File not found.")
        return

    password = getpass.getpass("Enter password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)
    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
