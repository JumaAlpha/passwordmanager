from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# Function to generate a random AES key
def generate_key():
    return os.urandom(32)  # 32 bytes for AES-256

# Function to encrypt a password using AES in CFB mode
def encrypt_password(password, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the password to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    # Encrypt the padded password
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    # Return the IV and the encrypted password as a base64 encoded string
    return base64.b64encode(iv + encrypted_password).decode('utf-8')

# Function to decrypt a password using AES in CFB mode
def decrypt_password(encrypted_password_base64, key):
    # Decode the base64 encoded string
    encrypted_data = base64.b64decode(encrypted_password_base64)

    # Extract the IV and the encrypted password
    iv = encrypted_data[:16]
    encrypted_password = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the encrypted password
    decrypted_padded_password = decryptor.update(encrypted_password) + decryptor.finalize()

    # Unpad the decrypted password
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_password = unpadder.update(decrypted_padded_password) + unpadder.finalize()

    return decrypted_password.decode('utf-8')

# Function to retrieve or create an encryption key
def get_encryption_key():
    key_path = 'database/encryption_key.key'

    # Check if the key file exists
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        # Generate a new key and save it
        key = generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        return key
