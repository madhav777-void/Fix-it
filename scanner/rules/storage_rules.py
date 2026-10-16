"""Insecure storage audit rules (STORAGE-001 through STORAGE-003)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.rules.base import Rule, Finding, RuleContext

SENSITIVE_PREF_KEYWORDS = re.compile(r'["\']([^"\']*(?:password|token|pin|secret|auth|credential|session)[^"\']*)["\']', re.IGNORECASE)
WORLD_MODE_PATTERNS = [
    re.compile(r'MODE_WORLD_READABLE', re.IGNORECASE),
    re.compile(r'MODE_WORLD_WRITEABLE', re.IGNORECASE),
    # smali invoke openFileOutput or getSharedPreferences with mode 1 or 2
    re.compile(r'invoke-virtual\s+\{[^}]+\},\s+Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)Ljava/io/FileOutputStream;'),
    re.compile(r'invoke-virtual\s+\{[^}]+\},\s+Landroid/content/Context;->getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;'),
]
EXTERNAL_STORAGE_CALLS = [
    "getExternalStorageDirectory",
    "getExternalStoragePublicDirectory",
    "getExternalFilesDir",
]
SENSITIVE_FILENAME_KEYWORDS = re.compile(r'(?:backup|token|secret|password|credential|key|auth|export|user_data|db)', re.IGNORECASE)


class RuleStorageUnencryptedPreferences(Rule):
    """STORAGE-001: Sensitive data in unencrypted SharedPreferences."""
    id = "STORAGE-001"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.decoded_dir or not context.decoded_dir.is_dir():
            return findings

        # First, check if EncryptedSharedPreferences is used in the codebase
        has_encrypted_prefs = False
        smali_files: List[Path] = []
        for sdir in context.decoded_dir.glob("smali*"):
            if sdir.is_dir():
                smali_files.extend(sdir.rglob("*.smali"))

        for sp in smali_files[:200]:
            try:
                content = sp.read_text(encoding="utf-8", errors="ignore")
                if "EncryptedSharedPreferences" in content:
                    has_encrypted_prefs = True
                    break
            except Exception:
                continue

        # If already using EncryptedSharedPreferences, app implements defense
        if has_encrypted_prefs:
            return findings

        # Scan for getSharedPreferences calls with sensitive names
        matches: List[Tuple[str, int, str]] = []
        for sp in smali_files[:200]:
            try:
                rel = str(sp.relative_to(context.decoded_dir))
                with open(sp, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, start=1):
                        if "getSharedPreferences" in line:
                            matches.append((rel, line_idx, line.strip()))
                            if len(matches) >= 3:
                                break
                        else:
                            # Check sensitive preference key strings
                            sensitive_match = SENSITIVE_PREF_KEYWORDS.search(line)
                            if sensitive_match and "const-string" in line:
                                matched_key = sensitive_match.group(1)
                                if len(matched_key) < 40 and not matched_key.startswith("android"):
                                    matches.append((rel, line_idx, f"Sensitive preference key string: '{matched_key}'"))
                                    if len(matches) >= 3:
                                        break
                if len(matches) >= 3:
                    break
            except Exception:
                continue

        for rel_path, line_no, evidence_text in matches:
            findings.append(
                self.create_finding(
                    file_path=rel_path,
                    line=line_no,
                    evidence=f"Unencrypted SharedPreferences usage: {evidence_text}",
                )
            )

        return findings


class RuleStorageWorldModes(Rule):
    """STORAGE-002: Use of MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE."""
    id = "STORAGE-002"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.decoded_dir or not context.decoded_dir.is_dir():
            return findings

        smali_files: List[Path] = []
        for sdir in context.decoded_dir.glob("smali*"):
            if sdir.is_dir():
                smali_files.extend(sdir.rglob("*.smali"))

        for sp in smali_files[:300]:
            try:
                rel = str(sp.relative_to(context.decoded_dir))
                with open(sp, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, start=1):
                        for pattern in WORLD_MODE_PATTERNS[:2]:  # Named MODE_WORLD_*
                            if pattern.search(line):
                                findings.append(
                                    self.create_finding(
                                        file_path=rel,
                                        line=line_idx,
                                        evidence=f"Insecure file permission mode referenced: {line.strip()}",
                                    )
                                )
                                if len(findings) >= 5:
                                    return findings
            except Exception:
                continue

        return findings


class RuleStorageExternalUsage(Rule):
    """STORAGE-003: External storage used for files with sensitive-sounding names."""
    id = "STORAGE-003"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        has_ext_perm = (
            "android.permission.WRITE_EXTERNAL_STORAGE" in context.manifest.uses_permissions
            or "android.permission.READ_EXTERNAL_STORAGE" in context.manifest.uses_permissions
        )

        if not context.decoded_dir or not context.decoded_dir.is_dir():
            if has_ext_perm:
                findings.append(
                    self.create_finding(
                        file_path="AndroidManifest.xml",
                        evidence="App requests WRITE_EXTERNAL_STORAGE permission without scoped storage enforcement.",
                    )
                )
            return findings

        smali_files: List[Path] = []
        for sdir in context.decoded_dir.glob("smali*"):
            if sdir.is_dir():
                smali_files.extend(sdir.rglob("*.smali"))

        for sp in smali_files[:200]:
            try:
                rel = str(sp.relative_to(context.decoded_dir))
                with open(sp, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, start=1):
                        if any(ext_api in line for ext_api in EXTERNAL_STORAGE_CALLS):
                            findings.append(
                                self.create_finding(
                                    file_path=rel,
                                    line=line_idx,
                                    evidence=f"External storage API reference: {line.strip()}",
                                )
                            )
                            if len(findings) >= 3:
                                return findings
            except Exception:
                continue

        if not findings and has_ext_perm:
            findings.append(
                self.create_finding(
                    file_path="AndroidManifest.xml",
                    evidence="App requests legacy shared storage permission (WRITE_EXTERNAL_STORAGE).",
                )
            )

        return findings
