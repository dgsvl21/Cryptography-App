#Tests for AES-GCM encryption and decryption functions
import pytest
from cryptography.exceptions import InvalidTag
from cryptography_app.crypto.aes_gcm import (generate_key, encrypt, decrypt)

#Verify that the generated key is the correct length of 32 bytes
def test_generate_key():
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32  #AES-256 key size

#Verify if cypher and decipher operations work correctly in data recovery and integrity
def test_encrypt_decrypt():
    key = generate_key()
    original = b"Cryptography App - test message"
    nonce, ciphertext = encrypt(original, key)
    recovered = decrypt(nonce, ciphertext, key)
    assert recovered == original
    assert ciphertext != original
    assert len(nonce) == 12  #Nonce size for AES-GCM

#Verify that decryption fails with an incorrect key
def test_wrong_key():
    key = generate_key()
    wrong_key = generate_key()
    nonce, ciphertext = encrypt(b"Private message data", key)
    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, wrong_key)

#Verify that decryption fails with a modified nonce
def test_modified_ciphertext():
    key = generate_key()
    nonce, ciphertext = encrypt(b"Confidential message", key)
    modified = bytearray(ciphertext)
    modified[0] ^= 1 #Flip a bit in the ciphertext
    with pytest.raises(InvalidTag):
        decrypt(nonce, bytes(modified), key)

#Verify if the keys with the wrong size are rejected
def test_invalid_key_size():
    invalid_key = b"short_key"
    with pytest.raises(ValueError):
        encrypt(b"Data", invalid_key)

#Verify if the aad is authenticated
def test_authenticated_associated_data():
    key = generate_key()
    aad = b"file_version_1"
    nonce, ciphertext = encrypt(b"Secret data", key, aad)
    assert decrypt(nonce, ciphertext, key, aad) == b"Secret data"
    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key, b"wrong_version")

#Verify if is possible to cypher empty data
def test_empty_plaintext():
    key = generate_key()
    nonce, ciphertext = encrypt(b"", key)
    assert decrypt(nonce, ciphertext, key) == b""
