

import pytest
from cryptography_app.crypto.kdf import generate_salt, derive_key

def test_generate_salt_length():
    salt = generate_salt()

    assert isinstance(salt, bytes)
    assert len(salt) == 16

def test_unique_salts():
    salt1 = generate_salt()
    salt2 = generate_salt()

    assert salt1 != salt2

def test_derive_key_length():
    salt = generate_salt()

    key = derive_key("TestPassword123", salt)

    assert isinstance(key, bytes)
    assert len(key) == 32

def test_same_password_and_salt():
    password = "TestPassword123"
    salt = generate_salt()

    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)

    assert key1 == key2

def test_different_passwords():
    salt = generate_salt()

    key1 = derive_key("TestPassword123", salt)
    key2 = derive_key("DifferentPassword456", salt)

    assert key1 != key2

def test_different_salts():
    password = "TestPassword123"

    key1 = derive_key(password, generate_salt())
    key2 = derive_key(password, generate_salt())

    assert key1 != key2

def test_empty_password():
    salt = generate_salt()

    with pytest.raises(ValueError):
        derive_key("", salt)

def test_invalid_salt():
    with pytest.raises(ValueError):
        derive_key("TestPassword123", b"short")

def test_unicode_password():
    salt = generate_salt()

    key1 = derive_key("Passwordççç2026", salt)
    key2 = derive_key("Passwordççç2026", salt)

    assert key1 == key2
    assert len(key1) == 32