#!/usr/bin/env python3
"""
Helper script to download apktool.jar into bin/apktool.jar for local execution.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

DEFAULT_APKTOOL_VERSION = "2.9.3"
DOWNLOAD_URL = (
    f"https://github.com/iBotPeaches/Apktool/releases/download/v{DEFAULT_APKTOOL_VERSION}/apktool_{DEFAULT_APKTOOL_VERSION}.jar"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT_ROOT / "bin"
TARGET_FILE = TARGET_DIR / "apktool.jar"


def report_progress(block_num: int, block_size: int, total_size: int) -> None:
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100.0, (downloaded / total_size) * 100)
        mb_down = downloaded / (1024 * 1024)
        mb_total = total_size / (1024 * 1024)
        sys.stdout.write(f"\rDownloading apktool.jar: {percent:.1f}% ({mb_down:.1f}/{mb_total:.1f} MB)")
        sys.stdout.flush()


def download_apktool() -> None:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    if TARGET_FILE.exists() and TARGET_FILE.stat().st_size > 1_000_000:
        print(f"[OK] apktool.jar already exists at: {TARGET_FILE}")
        return

    print(f"Downloading Apktool v{DEFAULT_APKTOOL_VERSION}...")
    print(f"Source: {DOWNLOAD_URL}")
    print(f"Target: {TARGET_FILE}")

    try:
        # Use user-agent to avoid potential 403 blocks from GitHub CDN
        req = urllib.request.Request(
            DOWNLOAD_URL,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Apktool-Downloader/1.0"},
        )
        with urllib.request.urlopen(req) as response, open(TARGET_FILE, "wb") as out_file:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 64 * 1024
            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break
                out_file.write(buffer)
                downloaded += len(buffer)
                if total_size > 0:
                    percent = min(100.0, (downloaded / total_size) * 100)
                    sys.stdout.write(f"\rDownloading apktool.jar: {percent:.1f}% ({downloaded / (1024*1024):.1f}/{total_size / (1024*1024):.1f} MB)")
                    sys.stdout.flush()

        print("\n[OK] apktool.jar downloaded successfully!")
    except Exception as e:
        if TARGET_FILE.exists():
            TARGET_FILE.unlink(missing_ok=True)
        print(f"\n[ERROR] Failed to download apktool.jar: {e}", file=sys.stderr)
        print("Please download apktool manually from https://github.com/iBotPeaches/Apktool/releases", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    download_apktool()
