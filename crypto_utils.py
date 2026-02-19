import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

class SecurityManager:
    """
    Handles Advanced Encryption Standard (AES) with Galois/Counter Mode (GCM).
    This provides authenticated encryption with associated data (AEAD).
    While not strictly "Quantum Safe" (which requires specific PQC algorithms like Kyber/Dilithium),
    AES-256 is generally considered resistant to quantum computer attacks (Grover's algorithm)
    due to its key size (requires 2^128 operations on a quantum computer).
    """
    def __init__(self, key=None):
        # Generate a 256-bit key if not provided (AES-256)
        # In a real deployed app, this key should be persistent and stored securely (e.g., Vault, HSM, or Env Var)
        self.key = key if key else AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.
        Returns (nonce, ciphertext).
        """
        nonce = secrets.token_bytes(12)  # NIST recommended nonce size
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        """
        Decrypts ciphertext using AES-256-GCM.
        """
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed: Integrity check failed or invalid key/nonce.") from e

# Singleton instance for the app session (in memory key for demo, normally from env)
# Ideally, we load this from an environment variable to persist across restarts.
try:
    _env_key = os.environ.get("ENCRYPTION_KEY")
    if _env_key:
        # Expect hex string
        _key_bytes = bytes.fromhex(_env_key)
        security_manager = SecurityManager(_key_bytes)
    else:
        # Fallback to ephemeral key (forcing re-login on restart)
        # This is safer than a hardcoded key.
        security_manager = SecurityManager()
except Exception:
    security_manager = SecurityManager()
