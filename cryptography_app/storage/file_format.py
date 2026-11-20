#Binary encrypted file format
import struct
from dataclasses import dataclass
from cryptography_app.crypto.kdf import TIME_COST, MEMORY_COST, PARALLELISM, SALT_SIZE
from cryptography_app.crypto.aes_gcm import NONCE_SIZE

MAGIC = b"SFEN" #4 Bytes to identify the file as a secure file encrypted with this app
VERSION = 1 #format version
TAG_SIZE = 16 #16 bytes for the authentication tag
HEADER = struct.Struct(">4sB16s12sIII") #big-endian struct format for the file header: magic, version, salt, nonce, time_cost, memory_cost, parallelism

#Validate the componentes of an encrypted file
@dataclass(frozen=True) #data class to represent the structure of encrypted file data
class EncryptedFileData:
    salt:bytes #16 bytes
    nonce:bytes #12 bytes
    ciphertext:bytes #variable length
    aad:bytes #additional authenticated data, and it contains exactly 45bytes of the header

#build and encrypted file container
def pack_encrypted_data(salt:bytes, nonce:bytes, ciphertext:bytes) -> bytes: #receive salt, nonce and ciphertext, validates and build a byte sequence 
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce")
    if not isinstance(ciphertext, bytes):
        raise ValueError("Invalid ciphertext")
    if len(ciphertext) < TAG_SIZE:
        raise ValueError("Ciphertext too short")

    header = HEADER.pack(MAGIC, VERSION, salt, nonce, TIME_COST, MEMORY_COST, PARALLELISM)
    return header + ciphertext

#Parse and validate an encrypted file container
def unpack_encrypted_data(data:bytes) -> EncryptedFileData: #read a binary sequence and return a packed encrypted file container
    if not isinstance(data, bytes):
        raise TypeError("Encrypted data must be bytes")
    if len(data) < HEADER.size + TAG_SIZE:
        raise ValueError("Encrypted file too short")

    header = data[:HEADER.size]
    ciphertext = data[HEADER.size:]
    magic, version, salt, nonce, time_cost, memory_cost, parallelism = HEADER.unpack(header)

    if magic != MAGIC:
        raise ValueError("Invalid encrypted file signature")
    if version != VERSION:
        raise ValueError("Unsupported file version")
    if (time_cost != TIME_COST or memory_cost != MEMORY_COST or parallelism != PARALLELISM):
        raise ValueError("Invalid KDF parameters")

    return EncryptedFileData(salt=salt, nonce=nonce, ciphertext=ciphertext, aad=header)