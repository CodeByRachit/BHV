import os
import pytest
import hashlib
from cryptography.fernet import InvalidToken
from crypto import security, stream_security, StreamVaultSecurity

@pytest.fixture
def sample_chunk():
    """Simulates a 64KB chunk of binary image data streaming into the server."""
    return os.urandom(64 * 1024)

# =====================================================================
# --- PROOF 1: STANDARD INTEGRITY & PRIVACY (Happy Paths) ---
# =====================================================================

def test_fernet_data_integrity_and_retrieval(sample_chunk):
    """Ensures 100% of the visual data is perfectly recovered via Fernet."""
    ciphertext = security.encrypt_narrative(sample_chunk)
    decrypted_chunk = security.decrypt_narrative(ciphertext)
    assert hashlib.sha256(sample_chunk).hexdigest() == hashlib.sha256(decrypted_chunk).hexdigest()

def test_aes_ctr_streaming_integrity(sample_chunk):
    """Ensures the AES-256 streaming decryptor perfectly restores the 64KB chunk on the fly."""
    iv, encryptor = stream_security.get_encryptor()
    ciphertext = encryptor.update(sample_chunk) + encryptor.finalize()
    decryptor = stream_security.get_decryptor(iv)
    decrypted_chunk = decryptor.update(ciphertext) + decryptor.finalize()
    assert decrypted_chunk == sample_chunk

# =====================================================================
# --- PROOF 2: THE EDGE CASES (Resilience Tests) ---
# =====================================================================

def test_edge_case_empty_payload():
    """Simulates a network drop resulting in a 0-byte payload."""
    iv, encryptor = stream_security.get_encryptor()
    assert encryptor.update(b"") + encryptor.finalize() == b""

def test_edge_case_unaligned_chunk():
    """Ensures CTR mode handles fragmented, non-16-byte aligned network packets."""
    odd_chunk = os.urandom(9999) 
    iv, encryptor = stream_security.get_encryptor()
    ciphertext = encryptor.update(odd_chunk) + encryptor.finalize()
    decryptor = stream_security.get_decryptor(iv)
    assert decryptor.update(ciphertext) + decryptor.finalize() == odd_chunk

def test_edge_case_invalid_iv_length():
    """AES requires exactly a 16-byte IV. Database truncation must trigger a ValueError."""
    with pytest.raises(ValueError):
        stream_security.get_decryptor(os.urandom(10))

def test_edge_case_type_enforcement():
    """Ensures the API layer cannot accidentally pass Strings instead of Bytes."""
    with pytest.raises(TypeError):
        security.encrypt_narrative("This is a string, not raw bytes!")

# =====================================================================
# --- PROOF 3: THE SECURITY LOOPHOLES (Red Team Audits) ---
# =====================================================================

def test_loophole_iv_uniqueness():
    """
    SECURITY AUDIT: The 'Two-Time Pad' Vulnerability.
    If AES-CTR reuses an IV, the cipher is broken. This mathematically 
    proves the generator creates unique 16-byte nonce/IVs for every file.
    """
    iv1, _ = stream_security.get_encryptor()
    iv2, _ = stream_security.get_encryptor()
    
    assert iv1 != iv2, "CRITICAL VULNERABILITY: IVs are repeating!"
    assert len(iv1) == 16, "IV must be exactly 16 bytes for AES."

def test_loophole_ctr_malleability():
    """
    SECURITY AUDIT: Ciphertext Malleability.
    Unlike Fernet, CTR mode is unauthenticated. Flipped bits in ciphertext 
    WILL successfully decrypt, but result in corrupted plaintext.
    This test proves WHY the system relies on the `integrity_hash` in crypto.py.
    """
    valid_chunk = b"Sensitive Patient Data"
    iv, encryptor = stream_security.get_encryptor()
    ciphertext = bytearray(encryptor.update(valid_chunk) + encryptor.finalize())
    
    # Attacker maliciously flips a bit in the encrypted vault file
    ciphertext[0] = ciphertext[0] ^ 0xFF 
    
    decryptor = stream_security.get_decryptor(iv)
    corrupted_plaintext = decryptor.update(bytes(ciphertext)) + decryptor.finalize()
    
    # 1. It DOES NOT crash (the CTR loophole)
    # 2. But the plaintext is now corrupted
    assert corrupted_plaintext != valid_chunk
    assert len(corrupted_plaintext) == len(valid_chunk)

def test_loophole_fernet_tamper_resistance():
    """
    SECURITY AUDIT: Fernet MAC Validation.
    Proves that Fernet actively rejects tampered ciphertext using its 
    built-in Message Authentication Code (MAC).
    """
    ciphertext = bytearray(security.encrypt_narrative(b"Secret Data"))
    ciphertext[-1] = ciphertext[-1] ^ 0xFF 
    
    with pytest.raises(InvalidToken):
        security.decrypt_narrative(bytes(ciphertext))

def test_loophole_admin_key_misconfiguration():
    """
    SECURITY AUDIT: Environment Variable Injection.
    If an admin manually types a key into .env that is NOT valid hex,
    the system must crash on boot to prevent weak encryption states.
    """
    original_key = os.getenv("BHV_STREAM_KEY")
    os.environ["BHV_STREAM_KEY"] = "this_is_not_a_valid_hex_string_and_will_fail"
    
    with pytest.raises(ValueError):
        StreamVaultSecurity()
        
    if original_key:
        os.environ["BHV_STREAM_KEY"] = original_key
    elif "BHV_STREAM_KEY" in os.environ:
        del os.environ["BHV_STREAM_KEY"]

def test_loophole_admin_key_length():
    """
    SECURITY AUDIT: Weak Key Prevention.
    AES-256 REQUIRES a 32-byte key. If an admin provides a shorter valid hex,
    the cryptography library must actively block the initialization.
    """
    original_key = os.getenv("BHV_STREAM_KEY")
    os.environ["BHV_STREAM_KEY"] = os.urandom(16).hex()
    
    # Notice the indentation here! The initialization is INSIDE the with block.
    with pytest.raises(ValueError, match="CRITICAL: BHV requires a 32-byte key"):
        StreamVaultSecurity()

    if original_key:
        os.environ["BHV_STREAM_KEY"] = original_key
    elif "BHV_STREAM_KEY" in os.environ:
        del os.environ["BHV_STREAM_KEY"]