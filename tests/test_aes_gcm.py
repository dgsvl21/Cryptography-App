#Tests for AES-GCM encryption and decryption functions
import pytest
from cryptography.exceptions import InvalidTag
from cryptography_app.crypto.aes_gcm import (generate_key, encrypt, decrypt)

def test_generate_key():
    key = generate_key()

    assert isinstance(key, bytes)
    assert len(key) == 32  #AES-256 key size

def test_encrypt_decrypt():
    key = generate_key()
    original = b"Cryptography App - test message"

    nonce, ciphertext = encrypt(original, key)
    recovered = decrypt(nonce, ciphertext, key)

    assert recovered == original
    assert ciphertext != original
    assert len(nonce) == 12  #Nonce size for AES-GCM

def test_wrong_key():
    key = generate_key()
    wrong_key = generate_key()

    nonce, ciphertext = encrypt(b"Private message data", key)

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, wrong_key)

def test_modified_ciphertext():
    key = generate_key()

    nonce, ciphertext = encrypt(b"Confidential message", key)

    modified = bytearray(ciphertext)
    modified[0] ^= 1 #Flip a bit in the ciphertext

    with pytest.raises(InvalidTag):
        decrypt(nonce, bytes(modified), key)

def test_invalid_key_size():
    invalid_key = b"short_key"

    with pytest.raises(ValueError):
        encrypt(b"Data", invalid_key)

def test_authenticated_associated_data():
    key = generate_key()
    aad = b"file_version_1"

    nonce, ciphertext = encrypt(b"Secret data", key, aad)

    assert decrypt(nonce, ciphertext, key, aad) == b"Secret data"

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key, b"wrong_version")

def test_empty_plaintext():
    key = generate_key()

    nonce, ciphertext = encrypt(b"", key)

    assert decrypt(nonce, ciphertext, key) == b""
