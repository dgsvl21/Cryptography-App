#Argon2id Key Derivation Function (KDF) implementation using the argon2-cffi library

import os
from argon2.low_level import Type, hash_secret_raw

#Constant definitions
SALT_SIZE = 16  #Recommended size for Argon2id salt
KEY_SIZE = 32  #Desired key size for derived keys
TIME_COST = 2  #Number of iterations
MEMORY_COST = 65536  #Memory cost in kibibytes
PARALLELISM = 1  #Number of parallel threads

#Generate a random salt key for Argon2id KDF
def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

#Derive a 256-bit AES key from a password and salt using Argon2id KDF
def derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if not password:
        raise ValueError("Password cannot be empty")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must contain exactly {SALT_SIZE} bytes")

    #Convert the password to bytes for hashing
    password_bytes = password.encode('utf-8')

    #Derive the key using Argon2id KDF with specified parameters
    return hash_secret_raw(secret=password_bytes, salt=salt, time_cost=TIME_COST, memory_cost=MEMORY_COST, parallelism=PARALLELISM, hash_len=KEY_SIZE, type=Type.ID) 