"""Build and integrity rules (BUILD-001 through BUILD-003)."""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanner.rules.base import Rule, Finding, RuleContext

# APK Signing Block Magic 16 bytes: "APK Sig Block 42"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def _check_apk_signing_schemes(apk_path: Path) -> Dict[str, bool]:
    """
    Inspect APK zip file to detect Signature Scheme v1 (META-INF)
    and Signature Scheme v2/v3 (APK Signing Block).
    """
    result = {"v1": False, "v2_v3": False, "debug_cert": False}
    if not apk_path.is_file():
        return result

    try:
        # Check v1 signature in META-INF
        with zipfile.ZipFile(apk_path, "r") as zf:
            meta_files = [f for f in zf.namelist() if f.startswith("META-INF/")]
            has_sig_file = any(f.endswith((".RSA", ".DSA", ".EC", ".SF")) for f in meta_files)
            if has_sig_file:
                result["v1"] = True

            # Check for Debug Certificate in META-INF signature files
            for cert_file in meta_files:
                if cert_file.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
                    content = zf.read(cert_file)
                    if b"Android Debug" in content or b"CN=Android Debug" in content or b"Android,OU=Android" in content:
                        result["debug_cert"] = True
                        break
    except Exception:
        pass

    try:
        # Check v2/v3 APK Signing Block
        with open(apk_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # The APK Signing block is immediately before the ZIP Central Directory.
            # Read the last 65KB to locate the magic bytes "APK Sig Block 42".
            scan_size = min(size, 65536 * 2)
            f.seek(size - scan_size)
            chunk = f.read(scan_size)
            if APK_SIG_BLOCK_MAGIC in chunk:
                result["v2_v3"] = True
    except Exception:
        pass

    return result


class RuleBuildObfuscation(Rule):
    """BUILD-001: No evidence of R8/ProGuard obfuscation."""
    id = "BUILD-001"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.decoded_dir or not context.decoded_dir.is_dir():
            return findings

        smali_files: List[Path] = []
        for sdir in context.decoded_dir.glob("smali*"):
            if sdir.is_dir():
                smali_files.extend(sdir.rglob("*.smali"))

        if not smali_files:
            return findings

        # Check for single-letter obfuscated classes or directories (e.g. a/b/c.smali, a.smali)
        has_obfuscation = False
        sample = smali_files[:300]
        for sp in sample:
            parts = sp.relative_to(context.decoded_dir).parts
            # If any package segment or class name is single letter (e.g. 'a', 'b', 'c.smali')
            for part in parts[1:]:  # skip 'smali'
                name_clean = part.replace(".smali", "")
                if len(name_clean) <= 2 and name_clean.isalnum():
                    has_obfuscation = True
                    break
            if has_obfuscation:
                break

        if not has_obfuscation:
            findings.append(
                self.create_finding(
                    file_path="smali/",
                    evidence="All decompiled smali packages and classes retain readable descriptive names. No R8/ProGuard renaming detected.",
                )
            )

        return findings


class RuleBuildSigningScheme(Rule):
    """BUILD-002: Signing scheme check: APK Signature Scheme v1-only detected."""
    id = "BUILD-002"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.apk_path or not context.apk_path.is_file():
            return findings

        sig_info = _check_apk_signing_schemes(context.apk_path)
        if sig_info["v1"] and not sig_info["v2_v3"]:
            findings.append(
                self.create_finding(
                    file_path=context.apk_path.name,
                    evidence="APK contains META-INF JAR signature (Scheme v1) but lacks modern APK Signature Scheme v2/v3 block.",
                )
            )

        return findings


class RuleBuildDebugCertificate(Rule):
    """BUILD-003: Debug certificate signature detected."""
    id = "BUILD-003"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.apk_path or not context.apk_path.is_file():
            return findings

        sig_info = _check_apk_signing_schemes(context.apk_path)
        if sig_info["debug_cert"]:
            findings.append(
                self.create_finding(
                    file_path=context.apk_path.name,
                    evidence="APK signing certificate Subject contains 'CN=Android Debug'. The APK is signed with a public development key.",
                )
            )

        return findings
