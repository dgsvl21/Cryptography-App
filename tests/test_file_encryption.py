#Integration tests for local file encryption

import pytest
from cryptography.exceptions import InvalidTag
from cryptography_app.services.file_encryption import encrypt_file, decrypt_file, MAX_INPUT_SIZE

#Verify if a file encryption and decryption recover exactly the original bytes
def test_round_trip(tmp_path):
    source = tmp_path / "original.txt"
    source.write_bytes(b"Scret\x00Data")
    encrypted = tmp_path / "original.sfe"
    restored = tmp_path / "restored.txt"
    encrypt_file(source, encrypted, "StrongPassword!")
    assert encrypted.read_bytes() != source.read_bytes()
    decrypt_file(encrypted, restored, "StrongPassword!")
    assert restored.read_bytes() == source.read_bytes()

#Verify if an incorrect password does not produce a decryped file
def test_wrong_password_does_not_create_output(tmp_path):
    source = tmp_path / "original.txt"
    source.write_bytes(b"Confidential")
    encrypted = tmp_path / "original.sfe"
    restored = tmp_path / "restored.txt"
    encrypt_file(source, encrypted, "correct!")
    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, "wrong")
    assert not restored.exists()

#Verify if modififications to encrypted content are detected 
def test_tampered_ciphertext_is_rejected(tmp_path):
    source = tmp_path / "original.txt"
    source.write_bytes(b"Confidential")
    encrypted = tmp_path / "original.sfe"
    restored = tmp_path / "restored.txt"
    encrypt_file(source, encrypted, "correct!")
    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)
    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, "correct")
    assert not restored.exists()

#Verify if modififications to authenticated salt are detected
def test_tampered_header_is_rejected(tmp_path):
    source = tmp_path / "original.txt"
    source.write_bytes(b"Confidential")
    encrypted = tmp_path / "original.sfe"
    restored = tmp_path / "restored.txt"
    encrypt_file(source, encrypted, "correct!")
    data = bytearray(encrypted.read_bytes())
    data[5] ^= 1 #Modify one byte of the salt in the authenticated header
    encrypted.write_bytes(data)
    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, "correct")
    assert not restored.exists()

#Verify if existing file are not overwritten
def test_reject_overwrite(tmp_path):
    source = tmp_path / "original.txt"
    source.write_bytes(b"Hi")
    encrypted = tmp_path / "original.sfe"
    encrypted.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        encrypt_file(source, encrypted, "secret")
    assert encrypted.read_bytes() == b"keep"

#Verify if identical input and output file paths are rejected
def test_reject_same_source_destination(tmp_path):
    source = tmp_path / "original.sfe"
    source.write_bytes(b"Hi")
    with pytest.raises(ValueError):
        encrypt_file(source, source, "secret")
    assert source.read_bytes() == b"Hi"

#Verify if empty files are supported
def test_empty_file(tmp_path):
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")
    encrypted = tmp_path / "empty.sfe"
    restored = tmp_path / "restored.txt"
    encrypt_file(source, encrypted, "secret")
    decrypt_file(encrypted, restored, "secret")
    assert restored.read_bytes() == b""

#Verify if corrupted .sfe files are rejected
def test_invalid_containers(tmp_path):
    source = tmp_path / "broken.sfe"
    source.write_bytes(b"not valid")
    restored = tmp_path / "restored.txt"
    with pytest.raises(ValueError):
        decrypt_file(source, restored, "secret")
    assert not restored.exists()

#Verify in files exceeding the initial size limit are rejected
def test_size_limit(tmp_path):
    source = tmp_path / "large.sfe"
    source.write_bytes(b"x" * (MAX_INPUT_SIZE + 1))
    encrypted = tmp_path / "larfe.sfe"
    with pytest.raises(ValueError):
        encrypt_file(source, encrypted, "secret")
    assert not encrypted.exists()
