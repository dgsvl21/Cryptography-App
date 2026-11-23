#AES-GCM encryption and decryption module

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constant definitions#
KEY_SIZE = 32  #AES-256, 32 bytes equeals to 256 bits
NONCE_SIZE = 12  #recommended size for GCM nonce, 12 bytes equals to 96 bits

#Generate a random AES-256 key
def generate_key() -> bytes: 
    return AESGCM.generate_key(bit_length=256) #key generation, returns a random 32-byte key for AES-256 encryption

#Encrypt data using a custom nonce
def encrypt_with_nonce(plaintext:bytes, key:bytes, nonce:bytes, aad:bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE: #encrypt with a caller provided nonce, never reuse the same key and nonce combination
        raise ValueError("AES-256 rquires a 32 byte key")
    
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must have 12 bytes")
    
    return AESGCM(key).encrypt(nonce, plaintext, aad) 

#Encrypt data and return the nonce and ciphertext with tag
def encrypt(plaintext: bytes, key: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32 byte key")

    nonce = os.urandom(NONCE_SIZE) #generate a random nonce for each encryption operation

    aesgcm = AESGCM(key) #execute a AES-GCM encryption operation using the provided key and nonce

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad) #cypher: method that cypher data and produce information for authentication 
    
    return nonce, ciphertext

#Decrypt data using the provided nonce and key
def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, aad) #decipher: method that deciphers the data and verifies the authenticity of the ciphertext



