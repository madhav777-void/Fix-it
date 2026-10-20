"""APK Upload Validator and Apktool Decoder module."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional, Tuple, Union

ZIP_MAGIC_BYTES = b"PK\x03\x04"
MAX_APK_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB
DEFAULT_TIMEOUT_SECONDS = 120


class ValidationError(Exception):
    """Raised when an uploaded file fails security or format validation."""
    pass


class DecodeError(Exception):
    """Raised when decoding fails or apktool encounters an error."""
    pass


@dataclass
class DecodeResult:
    """Result of an APK decoding operation."""
    success: bool
    output_dir: Path
    apk_path: Path
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None
    duration_seconds: float = 0.0


def validate_apk_file(
    file_source: Union[Path, str, BinaryIO],
    original_filename: Optional[str] = None,
    max_size_bytes: int = MAX_APK_SIZE_BYTES,
) -> Tuple[bool, Optional[str]]:
    """
    Validate that the uploaded file:
    1. Has a filename ending in .apk (case-insensitive)
    2. Does not exceed max_size_bytes (default: 200 MB)
    3. Has the valid ZIP magic bytes (PK\\x03\\x04)
    """
    # 1. Filename validation
    fname = original_filename
    if fname is None and isinstance(file_source, (str, Path)):
        fname = Path(file_source).name

    if not fname or not fname.lower().endswith(".apk"):
        return False, "File must have an .apk extension."

    # 2. File size and magic bytes check
    if isinstance(file_source, (str, Path)):
        path = Path(file_source)
        if not path.is_file():
            return False, f"File does not exist: {path}"
        size = path.stat().st_size
        if size == 0:
            return False, "Uploaded APK is empty (0 bytes)."
        if size > max_size_bytes:
            return False, f"File size ({size / (1024 * 1024):.1f} MB) exceeds maximum limit of {max_size_bytes / (1024 * 1024):.0f} MB."

        with open(path, "rb") as f:
            header = f.read(4)
    else:
        # File-like object (e.g. Werkzeug FileStorage stream)
        stream = file_source
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(0)

        if size == 0:
            return False, "Uploaded APK is empty (0 bytes)."
        if size > max_size_bytes:
            return False, f"File size ({size / (1024 * 1024):.1f} MB) exceeds maximum limit of {max_size_bytes / (1024 * 1024):.0f} MB."

        header = stream.read(4)
        stream.seek(0)

    if header != ZIP_MAGIC_BYTES:
        return False, "Invalid file format: missing ZIP magic bytes (PK\\x03\\x04)."

    return True, None


def save_upload(
    file_stream_or_path: Union[BinaryIO, Path, str],
    workspace_dir: Union[Path, str],
    original_filename: Optional[str] = None,
) -> Path:
    """
    Save the upload to workspace_dir using a random UUID filename.
    Never uses the user-provided filename in the stored path.
    """
    workspace = Path(workspace_dir)
    workspace.mkdir(parents=True, exist_ok=True)

    random_id = uuid.uuid4().hex
    safe_path = workspace / f"{random_id}.apk"

    if isinstance(file_stream_or_path, (str, Path)):
        shutil.copyfile(str(file_stream_or_path), str(safe_path))
    else:
        file_stream_or_path.seek(0)
        with open(safe_path, "wb") as f_out:
            shutil.copyfileobj(file_stream_or_path, f_out)
        file_stream_or_path.seek(0)

    return safe_path


def get_apktool_command() -> Optional[list[str]]:
    """Determine the command to invoke apktool on the host system."""
    custom_cmd = os.environ.get("APKTOOL_CMD")
    if custom_cmd:
        return [custom_cmd]

    # Check PATH for apktool or apktool.bat
    found = shutil.which("apktool") or shutil.which("apktool.bat")
    if found:
        return [found]

    # Check common jar location
    apktool_jar = os.environ.get("APKTOOL_JAR")
    if apktool_jar and Path(apktool_jar).is_file():
        java = shutil.which("java") or "java"
        return [java, "-Xmx384m", "-jar", apktool_jar]

    # Check local project bin or root folder for apktool.jar
    project_root = Path(__file__).resolve().parent.parent
    local_jars = [
        project_root / "bin" / "apktool.jar",
        project_root / "apktool.jar",
    ]
    for jar in local_jars:
        if jar.is_file():
            java = shutil.which("java") or "java"
            return [java, "-Xmx384m", "-jar", str(jar)]

    return None


def decode_apk(
    apk_path: Union[Path, str],
    output_dir: Union[Path, str],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    apktool_cmd: Optional[list[str]] = None,
) -> DecodeResult:
    """
    Run apktool decode on the specified APK with timeout and error capturing.
    Command: apktool decode -f -o <output_dir> <apk_path>
    """
    apk_p = Path(apk_path).resolve()
    out_p = Path(output_dir).resolve()

    if not apk_p.is_file():
        return DecodeResult(
            success=False,
            output_dir=out_p,
            apk_path=apk_p,
            error=f"APK file not found: {apk_p}",
        )

    cmd = apktool_cmd or get_apktool_command()
    if not cmd:
        return DecodeResult(
            success=False,
            output_dir=out_p,
            apk_path=apk_p,
            error=(
                "apktool is not installed or not found on PATH. "
                "Please install apktool and ensure it is in your system PATH, "
                "or set the APKTOOL_CMD or APKTOOL_JAR environment variable."
            ),
        )

    # For large APKs (>= 30 MB), add -s (--no-src) to skip smali decompilation.
    # Unpacking and decompiling 50,000+ smali files on large APKs exceeds
    # container memory limits (512 MB) and triggers worker timeouts or OOM kills.
    # Security manifest rules, network rules, permission checks, XML secrets,
    # and signing scheme checks still execute at 100% fidelity.
    flags = ["d", "-f"]
    try:
        if apk_p.stat().st_size >= 30 * 1024 * 1024:
            flags.append("-s")
    except Exception:
        pass

    full_cmd = cmd + flags + ["-o", str(out_p), str(apk_p)]
    start_time = time.monotonic()

    try:
        proc = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration = time.monotonic() - start_time

        if proc.returncode != 0:
            error_msg = proc.stderr.strip() or proc.stdout.strip() or f"apktool failed with exit code {proc.returncode}"
            return DecodeResult(
                success=False,
                output_dir=out_p,
                apk_path=apk_p,
                stdout=proc.stdout,
                stderr=proc.stderr,
                error=error_msg,
                duration_seconds=duration,
            )

        return DecodeResult(
            success=True,
            output_dir=out_p,
            apk_path=apk_p,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_seconds=duration,
        )

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start_time
        return DecodeResult(
            success=False,
            output_dir=out_p,
            apk_path=apk_p,
            error=f"apktool timed out after {timeout_seconds} seconds.",
            duration_seconds=duration,
        )
    except Exception as e:
        duration = time.monotonic() - start_time
        return DecodeResult(
            success=False,
            output_dir=out_p,
            apk_path=apk_p,
            error=f"Unexpected error running apktool: {str(e)}",
            duration_seconds=duration,
        )


def cleanup_directory(path: Union[Path, str]) -> None:
    """Safely remove a directory or file."""
    p = Path(path)
    if not p.exists():
        return
    try:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
    except Exception:
        pass
