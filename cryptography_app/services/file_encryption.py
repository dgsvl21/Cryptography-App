#Password-based file encryption

import os
import tempfile
from pathlib import Path
from cryptography_app.crypto.aes_gcm import NONCE_SIZE, encrypt_with_nonce, decrypt
from cryptography_app.crypto.kdf import generate_salt, derive_key, TIME_COST, MEMORY_COST, PARALLELISM
from cryptography_app.storage.file_format import MAGIC, VERSION, HEADER, TAG_SIZE, pack_encrypted_data, unpack_encrypted_data

#Initial limite for in memory file processing, to prevent excessice RAM usage 
MAX_INPUT_SIZE = 32 * 1024 * 1024 #32 MiB

#Read a file while enforcing the configured size limit
def _read_limited(path:Path, max_size:int) -> bytes:
    with path.open("rb") as file:
        data = file.read(max_size + 1)

        if len(data) > max_size:
            raise ValueError("Input file exceeds the supported size limit")

    return data

#Prevent identical input and output paths
def _validate_paths(source:Path, destination:Path) -> None:
    if source.resolve() == destination.resolve():
        raise ValueError("Input and output paths must be different")

#Safely publish a complete file without overwriting
def _write_new(path:Path, data:bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent) #Create a temporary file in the destination directory with a unique name and exclusive access
    temporary_path = Path(temporary_name)

    try: #Write the complete content to the temporary file
        with os.fdopen(fd, "wb") as file: #Open file descriptor for binary writing
            file.write(data) #Writes content
            file.flush() #Sent Python buffer data to the OS
            os.fsync(file.fileno()) #Request file data synchronization to disk
        os.link(temporary_path, path) #Publish only if the destination does not exist and requires hard-link support on the filesystem
    finally: #Remove the temporary name, even if publishing fails
        temporary_path.unlink(missing_ok=True)

# #Create a new output file without overwirting an existing one
# def _write_new(path:Path, data:bytes) -> None:
#     created = False
    
#     try:
#         with path.open("xb") as file:
#             file.write(data)
#     except BaseException:
#         if created:
#             path.unlink(missing_ok=True)
#         raise

#Encrypt a local file into a new .sfe container (integrate Argon2id, AES-GCM and .sfe)
def encrypt_file(source:str | Path, destination:str | Path, password: str) -> Path:
    source = Path(source)
    destination = Path(destination)

    _validate_paths(source, destination)

    if destination.suffix.lower() != ".sfe":
        raise ValueError("Encrypted output must be .sfe extension")

    plaintext = _read_limited(source, MAX_INPUT_SIZE)

    #Generate new crypthographic parameters
    salt = generate_salt()
    nonce = os.urandom(NONCE_SIZE)

    #Derive the AES-256 key from the password
    key = derive_key(password, salt)

    #Build the header before encryption
    header = HEADER.pack(MAGIC, VERSION, salt, nonce, TIME_COST, MEMORY_COST, PARALLELISM)

    #Authenticate the header additional data
    ciphertext = encrypt_with_nonce(plaintext, key, nonce, aad=header)

    container = pack_encrypted_data(salt, nonce, ciphertext)

    _write_new(destination, container)

    return destination

#Authenticate and decrypt an encrypted .sfe file
def decrypt_file(source:str | Path, destination:str | Path, password:str) -> Path:
    source = Path(source)
    destination = Path(destination)

    _validate_paths(source, destination)

    container = _read_limited(source, HEADER.size + MAX_INPUT_SIZE + TAG_SIZE)

    parsed = unpack_encrypted_data(container)

    #Recreate the encrypted key
    key = derive_key(password, parsed.salt)

    #Authentication must succeed before any output is written
    plaintext = decrypt(parsed.nonce, parsed.ciphertext, key, aad=parsed.aad)

    _write_new(destination, plaintext)

    return destination


    