import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from app.config import PBKDF_ITERATIONS, KEYLENGTH, SALT_LENGTH

class CryptoManager:
    def __init__(self, masterPassword:str, salt:bytes):
        self.salt = salt
        self.key = self._derive_key(masterPassword, salt)
        self.fernet = Fernet(self.key)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEYLENGTH,
            salt=salt,
            iterations=PBKDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self.fernet.decrypt(token)

    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(SALT_LENGTH)
    
    @staticmethod
    def generate_recovery_key() -> bytes:
        return Fernet.generate_key()
    