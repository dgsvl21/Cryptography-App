#Test cases for the KDF implementation
import pytest
from cryptography_app.crypto.kdf import generate_salt, derive_key

#Verify salt size
def test_generate_salt():
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == 16

#Verify if the two generated salts are unique
def test_unique_salts():
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert salt1 != salt2

#Verify derived key length as 32bytes and type
def test_derive_key_length():
    salt = generate_salt()
    key = derive_key("TestPassword123", salt)
    assert isinstance(key, bytes)
    assert len(key) == 32

#Confirms that the same password and salt produce the same derived key
def test_same_password_and_salt():
    password = "TestPassword123"
    salt = generate_salt()
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2

#Confirms if the other password changes the key
def test_different_passwords():
    salt = generate_salt()
    key1 = derive_key("TestPassword123", salt)
    key2 = derive_key("DifferentPassword456", salt)
    assert key1 != key2

#Confirms if other salt changes the password
def test_different_salts():
    password = "TestPassword123"
    key1 = derive_key(password, generate_salt())
    key2 = derive_key(password, generate_salt())
    assert key1 != key2

#Rejects a empty password
def test_empty_password():
    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_key("", salt)

#Rejects salts with a incorrect length
def test_invalid_salt():
    with pytest.raises(ValueError):
        derive_key("TestPassword123", b"short")

#Verify compatibility with unicode characters in the password
def test_unicode_password():
    salt = generate_salt()
    key1 = derive_key("Passwordççç2026", salt)
    key2 = derive_key("Passwordççç2026", salt)
    assert key1 == key2
    assert len(key1) == 32