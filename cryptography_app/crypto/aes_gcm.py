"""AES-GCM encryption and Decryption module"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

"""Constant definitions"""
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # Recommended size for GCM nonce

"""Generate a random AES-256 key"""
def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)

"""Encrypt data and return the nonce and ciphertext with tag."""
def encrypt(plaintext: bytes, key: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad) #Cipher
    
    return nonce, ciphertext

"""Decrypt data using the provided nonce and key"""
def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, aad) #Decipher




