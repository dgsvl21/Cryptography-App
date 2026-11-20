#Argon2id Key Derivation Function (KDF) implementation using the argon2-cffi library

import os
from argon2.low_level import Type, hash_secret_raw

#Constant definitions
SALT_SIZE = 16  #recommended size for Argon2id salt
KEY_SIZE = 32  #desired key size for derived keys
TIME_COST = 2  #number of iterations
MEMORY_COST = 65536  #memory cost in kibibytes
PARALLELISM = 1  #number of parallel threads

#Generate a random 16byte salt key for Argon2id KDF
def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE) #random bytes of length SALT_SIZE for the salt

#Derive a 256bit AES key from a password and salt using Argon2id KDF
def derive_key(password: str, salt: bytes) -> bytes: #passwiord chosen by the user and ramdomly generated salt
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if not password:
        raise ValueError("Password cannot be empty")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must contain exactly {SALT_SIZE} bytes")

    #Convert the password to bytes for hashing, format required by the cryptographic API 
    password_bytes = password.encode('utf-8')

    #Derive the key using Argon2id KDF with specified parameters with 32bytes, Type.ID specify Argon2id type for the KDF
    return hash_secret_raw(secret=password_bytes, salt=salt, time_cost=TIME_COST, memory_cost=MEMORY_COST, parallelism=PARALLELISM, hash_len=KEY_SIZE, type=Type.ID) 