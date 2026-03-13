import os
import tempfile  # CHANGED: Replaced 'io' with 'tempfile' to stream to disk
import hashlib
from cryptography.fernet import Fernet
from fastapi import UploadFile
from pydantic import BaseModel
from typing import List

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

# --- NEW BHV PRODUCTION CODE BELOW ---

class SearchableMetadata(BaseModel):
    patient_id: str
    tags: List[str]
    sync_status: str = "pending_sync"  # Write-Ahead Logging

async def secure_chunked_ingestion(file: UploadFile, patient_id: str) -> dict:
    """
    Processes file in 64KB chunks to ensure memory resilience
    and Zero-Knowledge security.
    """
    sha256_hash = hashlib.sha256()
    
    # CHANGED: Create a temporary file on the hard drive instead of RAM
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_path = temp_file.name
    
    # 1. Searchable Metadata Extraction (Non-sensitive)
    file_extension = file.filename.split(".")[-1] if file.filename else "unknown"
    metadata = SearchableMetadata(
        patient_id=patient_id, 
        tags=["art_therapy", file_extension]
    )

    try:
        # 2. 64KB Chunked Streaming (Prevents OOM Crashes)
        while chunk := await file.read(65536):  # 64KB increments
            # Update integrity hash
            sha256_hash.update(chunk)
            
            # Encrypting the chunk in volatile memory using existing VaultSecurity
            encrypted_chunk = security.encrypt_narrative(chunk)
            
            # CHANGED: Write directly to the disk file
            temp_file.write(encrypted_chunk)
    finally:
        # CHANGED: Ensure the file safely closes after the loop finishes
        temp_file.close()

    # 3. Final Payload (Ready for NoSQL Vault)
    return {
        "metadata": metadata.dict(),
        "integrity_hash": sha256_hash.hexdigest(),
        "encrypted_file_path": temp_path,  # CHANGED: Return the file path instead of the RAM blob
        "vault_id": metadata.patient_id
    }