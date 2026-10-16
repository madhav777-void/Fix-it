"""Tests for APK upload validation and apktool decoding."""

import io
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from scanner.decoder import (
    validate_apk_file,
    save_upload,
    decode_apk,
    cleanup_directory,
    ZIP_MAGIC_BYTES,
    MAX_APK_SIZE_BYTES,
)


@pytest.fixture
def valid_apk_bytes():
    """Create in-memory minimal valid zip/apk content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", "<manifest></manifest>")
    return buf.getvalue()


def test_validate_apk_valid(tmp_path, valid_apk_bytes):
    apk_path = tmp_path / "sample_app.apk"
    apk_path.write_bytes(valid_apk_bytes)

    valid, err = validate_apk_file(apk_path)
    assert valid is True
    assert err is None


def test_validate_apk_invalid_extension(tmp_path, valid_apk_bytes):
    fake_path = tmp_path / "sample_app.zip"
    fake_path.write_bytes(valid_apk_bytes)

    valid, err = validate_apk_file(fake_path)
    assert valid is False
    assert "must have an .apk extension" in err.lower()


def test_validate_apk_invalid_magic_bytes(tmp_path):
    fake_path = tmp_path / "not_an_apk.apk"
    fake_path.write_bytes(b"NOT_A_ZIP_HEADER_DATA")

    valid, err = validate_apk_file(fake_path)
    assert valid is False
    assert "magic bytes" in err.lower()


def test_validate_apk_empty_file(tmp_path):
    empty_path = tmp_path / "empty.apk"
    empty_path.write_bytes(b"")

    valid, err = validate_apk_file(empty_path)
    assert valid is False
    assert "empty" in err.lower()


def test_validate_apk_oversized(tmp_path, valid_apk_bytes):
    apk_path = tmp_path / "large.apk"
    apk_path.write_bytes(valid_apk_bytes)

    # Use small threshold for testing
    valid, err = validate_apk_file(apk_path, max_size_bytes=10)
    assert valid is False
    assert "exceeds maximum limit" in err.lower()


def test_validate_apk_file_stream(valid_apk_bytes):
    stream = io.BytesIO(valid_apk_bytes)
    valid, err = validate_apk_file(stream, original_filename="test_app.apk")
    assert valid is True
    assert err is None

    # Stream position should be preserved at 0
    assert stream.tell() == 0


def test_save_upload_random_uuid(tmp_path, valid_apk_bytes):
    workspace = tmp_path / "workspace"
    apk_source = tmp_path / "my_secret_name_user.apk"
    apk_source.write_bytes(valid_apk_bytes)

    saved_path = save_upload(apk_source, workspace, original_filename="my_secret_name_user.apk")

    assert saved_path.exists()
    assert saved_path.parent == workspace
    # Original filename should not be in saved path
    assert "my_secret_name_user" not in saved_path.name
    assert saved_path.suffix == ".apk"
    # Stem should be a valid 32-char hex UUID
    assert len(saved_path.stem) == 32


def test_decode_apk_missing_apktool(tmp_path, valid_apk_bytes):
    apk_path = tmp_path / "test.apk"
    apk_path.write_bytes(valid_apk_bytes)
    out_dir = tmp_path / "decoded"

    with patch("scanner.decoder.get_apktool_command", return_value=None):
        res = decode_apk(apk_path, out_dir, apktool_cmd=None)
        assert res.success is False
        assert "apktool is not installed" in res.error


def test_decode_apk_timeout(tmp_path, valid_apk_bytes):
    apk_path = tmp_path / "test.apk"
    apk_path.write_bytes(valid_apk_bytes)
    out_dir = tmp_path / "decoded"

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["apktool"], timeout=2)):
        res = decode_apk(apk_path, out_dir, timeout_seconds=2, apktool_cmd=["apktool"])
        assert res.success is False
        assert "timed out after 2 seconds" in res.error


def test_decode_apk_success_mock(tmp_path, valid_apk_bytes):
    apk_path = tmp_path / "test.apk"
    apk_path.write_bytes(valid_apk_bytes)
    out_dir = tmp_path / "decoded"

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "I: Decoding resources..."
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc):
        res = decode_apk(apk_path, out_dir, apktool_cmd=["apktool"])
        assert res.success is True
        assert res.output_dir == out_dir
        assert "Decoding resources" in res.stdout


def test_cleanup_directory(tmp_path):
    sub = tmp_path / "to_delete"
    sub.mkdir()
    (sub / "file.txt").write_text("temp")
    assert sub.exists()

    cleanup_directory(sub)
    assert not sub.exists()
