#Tests for safe file writing
import os
import pytest
from cryptography_app.services.file_encryption import _write_new

#Verify if the written file matches expected content
def test_safe_write_success(tmp_path):
    destination = tmp_path / "output.txt"
    _write_new(destination, b"Secure content")
    assert destination.read_bytes() == b"Secure content"

#Verify if overwriting an existing file is prevented
def test_existing_file_is_preserved(tmp_path):
    destination = tmp_path / "output.txt"
    destination.write_bytes(b"Original content")
    with pytest.raises(FileExistsError):
        _write_new(destination, b"New content")
    assert destination.read_bytes() == b"Original content"

#Verify if cleanup is performed after a successful operation
def test_temporary_file_removed_after_success(tmp_path):
    destination = tmp_path / "output.txt"
    _write_new(destination, b"Secure content")
    assert list(tmp_path.glob("*.tmp")) == []

#Verify if cleanup is performed after a failed operation
def test_temporary_file_removed_after_failure(tmp_path, monkeypatch):
    destination = tmp_path / "output.txt"
    def fail_publish(*args, **kwargs):
        raise OSError("Simulated publication failure")
    monkeypatch.setattr(os, "link", fail_publish)
    with pytest.raises(OSError):
        _write_new(destination, b"Secure content") 
    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []

#Verify if empty files are supported
def test_empty_file_can_be_written(tmp_path):
    destination = tmp_path / "empty.txt"
    _write_new(destination, b"")
    assert destination.exists()
    assert destination.read_bytes() == b""

#Verify if destinations in non-existing directories are rejected
def test_missing_directory(tmp_path):
    destination = tmp_path / "missing" / "output.txt"
    with pytest.raises(FileNotFoundError):
        _write_new(destination, b"Content")
    assert not destination.exists()

#Verify if a destination created by another process is not overwritten
def test_destination_created_during_publish(tmp_path, monkeypatch):
    destination = tmp_path / "output.txt"
    original_link = os.link
    def competing_publish(source, target):
        destination.write_bytes(b"Other process")
        return original_link(source, target)
    monkeypatch.setattr(os, "link", competing_publish)
    with pytest.raises(FileExistsError):
        _write_new(destination, b"Our content")
    assert destination.read_bytes() == b"Other process"
    assert list(tmp_path.glob("*.tmp")) == []
