import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_image(image_path: str, password: str, output_path: str):
    with open(image_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    file_key = Fernet.generate_key()
    fernet_data = Fernet(file_key)
    encrypted_data = fernet_data.encrypt(data)

    derived_key = derive_key(password, salt)
    fernet_key = Fernet(derived_key)
    encrypted_file_key = fernet_key.encrypt(file_key)

    with open(output_path, 'wb') as out:
        out.write(salt + b'||' + encrypted_file_key + b'||' + encrypted_data)

    print(f"Encrypted image saved as: {output_path}")

def decrypt_image(encrypted_path: str, password: str, output_path: str):
    with open(encrypted_path, 'rb') as f:
        content = f.read()

    salt, encrypted_file_key, encrypted_data = content.split(b'||', 2)

    derived_key = derive_key(password, salt)
    fernet_key = Fernet(derived_key)
    file_key = fernet_key.decrypt(encrypted_file_key)

    fernet_data = Fernet(file_key)
    decrypted_data = fernet_data.decrypt(encrypted_data)

    with open(output_path, 'wb') as out:
        out.write(decrypted_data)

    print(f"Decrypted image saved as: {output_path}")

# ---- Example usage ----
encrypt_image("img.jpg", "blabla", "img_encrypted.dat")
decrypt_image("img_encrypted.dat", "blabla", "img_decrypted.jpg")
