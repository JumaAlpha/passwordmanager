from Crypto.Cipher import AES
import os
import base64

def encrypt_password(password, key):
    """Encrypt a password using AES encryption in CFB mode."""
    # Generate a random initialization vector
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_password = cipher.encrypt(password.encode())
    
    # Return both IV and encrypted password, base64 encoded for storage
    return base64.b64encode(iv + encrypted_password).decode('utf-8')

def decrypt_password(encrypted_data, key):
    """Decrypt a previously encrypted password."""
    # Decode from base64
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]  # Extract the IV
    encrypted_password = encrypted_data[16:]  # The rest is the encrypted password
    
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_password = cipher.decrypt(encrypted_password)
    return decrypted_password.decode('utf-8')
