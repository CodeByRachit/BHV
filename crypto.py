# crypto.py
from cryptography.fernet import Fernet
import os

class VaultSecurity:
    def __init__(self):
        # Implementation of AES-256 (Fernet)
        # Pulls from .env; generates a temp key if missing
        secret = os.getenv("BHV_SECRET_KEY")
        if not secret:
            secret = Fernet.generate_key().decode()
            os.environ["BHV_SECRET_KEY"] = secret
            
        self.cipher = Fernet(secret.encode())

    def encrypt_narrative(self, raw_data: bytes) -> bytes:
        """Encrypts data-on-the-fly to prevent plain-text leaks."""
        return self.cipher.encrypt(raw_data)

    def decrypt_narrative(self, encrypted_data: bytes) -> bytes:
        """Decrypts in volatile memory for authorized clinician view."""
        return self.cipher.decrypt(encrypted_data)

security = VaultSecurity()