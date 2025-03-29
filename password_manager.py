import os
import json
from base64 import b64encode, b64decode
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class PasswordManager:
    def __init__(self, data_file='passwords.enc', key_file='master.key'):
        self.data_file = data_file
        self.key_file = key_file
        self.salt = b'salt_1234'  # In production, generate a random salt for each user
        self.backend = default_backend()

    def _derive_key(self, password: str) -> bytes:
        """Derive a 256-bit key from the master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def _get_encryption_key(self, password: str) -> bytes:
        """Get or create the encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                encrypted_key = f.read()
            derived_key = self._derive_key(password)

            # Decrypt the AES key with the derived key
            iv = encrypted_key[:16]
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            key = decryptor.update(encrypted_key[16:]) + decryptor.finalize()
            return key
        else:
            # Generate a new random AES key
            key = os.urandom(32)
            derived_key = self._derive_key(password)

            # Encrypt the AES key with the derived key
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            encrypted_key = iv + encryptor.update(key) + encryptor.finalize()

            with open(self.key_file, 'wb') as f:
                f.write(encrypted_key)
            return key

    def _encrypt_data(self, data: str, key: bytes) -> bytes:
        """Encrypt data using AES-256 in CBC mode"""
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def _decrypt_data(self, ciphertext: bytes, key: bytes) -> str:
        """Decrypt data using AES-256 in CBC mode"""
        iv = ciphertext[:16]
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()

    def save_password(self, service: str, username: str, password: str, master_password: str):
        """Save a password for a service"""
        key = self._get_encryption_key(master_password)

        # Load existing data
        data = {}
        if os.path.exists(self.data_file):
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self._decrypt_data(encrypted_data, key)
            data = json.loads(decrypted_data)

        # Add new entry
        data[service] = {
            'username': username,
            'password': password
        }

        # Save encrypted data
        encrypted_data = self._encrypt_data(json.dumps(data), key)
        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)

    def get_password(self, service: str, master_password: str) -> dict:
        """Retrieve a password for a service"""
        if not os.path.exists(self.data_file):
            raise FileNotFoundError("No passwords stored yet")

        key = self._get_encryption_key(master_password)

        with open(self.data_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self._decrypt_data(encrypted_data, key)
        data = json.loads(decrypted_data)

        if service not in data:
            raise KeyError(f"No entry found for service: {service}")

        return data[service]

    def list_services(self, master_password: str) -> list:
        """List all stored services"""
        if not os.path.exists(self.data_file):
            return []

        key = self._get_encryption_key(master_password)

        with open(self.data_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self._decrypt_data(encrypted_data, key)
        data = json.loads(decrypted_data)

        return list(data.keys())