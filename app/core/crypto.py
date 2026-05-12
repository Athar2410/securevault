import os
import hashlib
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )
    return kdf.derive(password.encode())

def encrypt_file(data: bytes, password: str) -> bytes:
    """Encrypt file bytes with AES-256-GCM. Returns single blob: salt+nonce+ciphertext."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # Pack everything into one binary blob: [salt(16)][nonce(12)][ciphertext]
    return salt + nonce + ciphertext

def decrypt_file(blob: bytes, password: str) -> bytes:
    """Decrypt AES-256-GCM blob. Raises InvalidTag if tampered."""
    salt       = blob[:16]
    nonce      = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def hash_file(data: bytes) -> str:
    """SHA-256 hash of plaintext — stored for integrity verification on download."""
    return hashlib.sha256(data).hexdigest()