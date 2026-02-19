from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import os
import base64
from dotenv import load_dotenv

load_dotenv()

class UserSecurityContext:
    """
    Manages encryption for a specific user using their credentials (password)
    as the key source. This allows data to persist in Redis and be
    recoverable only upon successful login.
    """
    def __init__(self, password: str, salt: bytes = None):
        if salt is None:
            self.salt = secrets.token_bytes(16)
        else:
            self.salt = salt
            
        # Derive a 32-byte (256-bit) key from the user's password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        self.aesgcm = AESGCM(key)

    def encrypt(self, data: str) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        return self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

class SecurityManager:
    """
    Server-side ephemeral encryption for session tokens.
    """
    def __init__(self, key=None):
        self.key = key if key else AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed") from e

# Initialize the global security manager
try:
    _env_key = os.environ.get("ENCRYPTION_KEY")
    if _env_key:
        _key_bytes = bytes.fromhex(_env_key)
        security_manager = SecurityManager(_key_bytes)
    else:
        security_manager = SecurityManager()
except Exception:
    security_manager = SecurityManager()
