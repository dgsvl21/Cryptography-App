#Test for saving encrypted results in a parsable format
import pytest
from cryptography.exceptions import InvalidTag
from cryptography_app.crypto.aes_gcm import generate_key, encrypt, decrypt
from cryptography_app.crypto.kdf import generate_salt, TIME_COST, MEMORY_COST, PARALLELISM
from cryptography_app.storage.file_format import MAGIC, VERSION, HEADER, EncryptedFileData, pack_encrypted_data, unpack_encrypted_data

def sample_container():
    salt = generate_salt()
    nonce = b"\x01" * 12
    ciphertext = b"\x02" * 32
    return pack_encrypted_data(salt, nonce, ciphertext)

#Verify if the data is correctly unpacked and recovered, preserving the salt, nonce ciphertext and aad
def test_pack_unpack():
    data = sample_container()
    parsed = unpack_encrypted_data(data)
    assert isinstance(parsed, EncryptedFileData)
    assert parsed.nonce == b"\x01" * 12
    assert parsed.ciphertext == b"\x02" * 32
    assert len(parsed.salt) == 16
    assert parsed.aad == data[:HEADER.size]

#Verify if the binary header has exactly 45 bytes
def test_header_size():
    assert HEADER.size == 45

#Verify if the files with an invalid magic number are rejected
def test_invalid_magic():
    data = bytearray(sample_container())
    data[0] ^= 1
    with pytest.raises(ValueError):
        unpack_encrypted_data(bytes(data))

#Verify what non suported format versions are rejected
def test_invalid_version():
    data = bytearray(sample_container())
    data[4] = 99
    with pytest.raises(ValueError):
        unpack_encrypted_data(bytes(data))

#Verify if both incompleted and short files are rejected
def test_truncated_file():
    with pytest.raises(ValueError):
        unpack_encrypted_data(b"SFEN")

#Verify what non suported Arogon2id are rejected
def test_invalid_kdf_parameters():
    data = bytearray(sample_container())
    data[HEADER.size - 1] ^= 1 #modify a byte in the parallelism field
    with pytest.raises(ValueError):
        unpack_encrypted_data(bytes(data))

#Verify if a incorrect salt lengh is not accepted
def test_invalid_salt():
    with pytest.raises(ValueError):
        pack_encrypted_data(b"short", b"\x01" * 12, b"\x02" * 32)

#Verify if a incorrect nonce lengh is not accepted
def test_invalid_nonce():
    with pytest.raises(ValueError):
        pack_encrypted_data(generate_salt(), b"short", b"\x02" * 32)

#Preparatory test, doesnt prove the herder authentication yet 
#Verify the header build to be used as AAD
def test_authenticated_header():
    key = generate_key()
    salt = generate_salt()

    #build the exact header that AES-GCM will authenticate
    nonce = b"\x03" * 12
    header = HEADER.pack(MAGIC, VERSION, salt, nonce, TIME_COST, MEMORY_COST, PARALLELISM) 

    #AES-GCM generetes its own nonce in the current API
    #use the returned nonce to build the final header instead
    nonce, _ = encrypt(b"temporary", key)
    header = HEADER.pack(MAGIC, VERSION, salt, nonce, TIME_COST, MEMORY_COST, PARALLELISM)

    #integration of header authentication will be complete
    assert len(header) == HEADER.size



