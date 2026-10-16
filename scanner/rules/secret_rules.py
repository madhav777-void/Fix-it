"""Secret and credential detection rules (SECRET-001) with mandatory redaction."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.rules.base import Rule, Finding, RuleContext

# Regex patterns for well-known secrets
SECRET_PATTERNS = [
    (
        "Google API Key",
        re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
        "High",
    ),
    (
        "AWS Access Key ID",
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "High",
    ),
    (
        "JSON Web Token (JWT) / Bearer Token",
        re.compile(r'\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b'),
        "High",
    ),
    (
        "Key/Secret Assignment Pattern",
        re.compile(
            r'["\']?(?:api[_-]?key|secret|token|auth[_-]?token|access[_-]?token|private[_-]?key|password)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.+=/]{12,})["\']',
            re.IGNORECASE,
        ),
        "High",
    ),
]

# XML string resource pattern: <string name="api_key">value</string>
XML_STRING_KEYWORD_REGEX = re.compile(
    r'<string\s+name=["\']([^"\']*(?:api_key|secret|token|password|auth|jwt)[^"\']*)["\']>([^<]+)</string>',
    re.IGNORECASE,
)

# Common false positives to exclude
FALSE_POSITIVE_SUBSTRINGS = {
    "androidx",
    "android",
    "schema",
    "com.google",
    "xmlns",
    "default",
    "placeholder",
    "change_me",
    "your_key",
    "app_name",
}


def redact_secret(val: str) -> str:
    """
    Mandatory secret redaction:
    Show first 4 and last 2 characters only, masked with ellipses.
    Example: 'AIzaSyD1234567890abcdefghijklmnopqrsXZ' -> 'AIza...XZ'
    """
    clean_val = val.strip()
    if len(clean_val) <= 6:
        return "[REDACTED]"
    return f"{clean_val[:4]}...{clean_val[-2:]}"


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)

    return entropy


class RuleHardcodedSecrets(Rule):
    """SECRET-001: Scan res/values, assets, and smali for hardcoded credentials and high-entropy secrets."""
    id = "SECRET-001"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        seen_redacted: Set[str] = set()

        entropy_threshold = float(context.settings.get("entropy_threshold", 4.0))
        entropy_min_len = int(context.settings.get("entropy_min_len", 20))

        # 1. Check AndroidManifest meta-data first
        for meta in context.manifest.app_meta_data:
            m_name_lower = meta.name.lower()
            val = meta.value or ""
            if not val:
                continue

            # Check if name suggests a key/token
            if any(k in m_name_lower for k in ("key", "secret", "token", "auth", "jwt", "password")):
                # Check known pattern or high entropy
                for label, pattern, severity in SECRET_PATTERNS:
                    m = pattern.search(val)
                    if m:
                        secret_val = m.group(1)
                        redacted = redact_secret(secret_val)
                        if redacted not in seen_redacted:
                            seen_redacted.add(redacted)
                            findings.append(
                                self.create_finding(
                                    file_path="AndroidManifest.xml",
                                    evidence=f"<meta-data android:name='{meta.name}'> containing {label}: {redacted}",
                                    custom_severity=severity,
                                    custom_title=f"Hardcoded {label} in AndroidManifest Meta-Data",
                                )
                            )
                        break
                else:
                    if len(val) >= 16 and calculate_shannon_entropy(val) >= 3.8:
                        redacted = redact_secret(val)
                        if redacted not in seen_redacted:
                            seen_redacted.add(redacted)
                            findings.append(
                                self.create_finding(
                                    file_path="AndroidManifest.xml",
                                    evidence=f"<meta-data android:name='{meta.name}'> high-entropy value: {redacted}",
                                    custom_severity="Medium",
                                    custom_title=f"Suspicious High-Entropy Credential in Meta-Data: '{meta.name}'",
                                )
                            )

        # 2. Check decoded directory if available
        if not context.decoded_dir or not context.decoded_dir.is_dir():
            return findings

        target_files: List[Path] = []

        # res/values/*.xml
        res_values = context.decoded_dir / "res" / "values"
        if res_values.is_dir():
            target_files.extend(res_values.glob("*.xml"))

        # assets/
        assets_dir = context.decoded_dir / "assets"
        if assets_dir.is_dir():
            for p in assets_dir.rglob("*"):
                if p.is_file() and p.stat().st_size < 1024 * 1024:  # Under 1MB
                    target_files.append(p)

        # smali/ string constants (sample up to 200 files if huge)
        smali_files = []
        for sdir in context.decoded_dir.glob("smali*"):
            if sdir.is_dir():
                smali_files.extend(sdir.rglob("*.smali"))
        target_files.extend(smali_files[:200])

        for file_path in target_files:
            rel_path = str(file_path.relative_to(context.decoded_dir))
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, start=1):
                        # Pattern scan
                        for label, pattern, severity in SECRET_PATTERNS:
                            matches = pattern.finditer(line)
                            for match in matches:
                                secret_val = match.group(1)
                                if any(fp in secret_val.lower() for fp in FALSE_POSITIVE_SUBSTRINGS):
                                    continue

                                redacted = redact_secret(secret_val)
                                key_id = f"{rel_path}:{redacted}"
                                if key_id not in seen_redacted:
                                    seen_redacted.add(key_id)
                                    findings.append(
                                        self.create_finding(
                                            file_path=rel_path,
                                            line=line_idx,
                                            evidence=f"Discovered {label}: {redacted}",
                                            custom_severity=severity,
                                            custom_title=f"Exposed {label}",
                                        )
                                    )
                                    if len(findings) >= 20:
                                        return findings

                        # XML string keywords
                        if file_path.suffix == ".xml":
                            xml_matches = XML_STRING_KEYWORD_REGEX.finditer(line)
                            for xm in xml_matches:
                                k_name = xm.group(1)
                                k_val = xm.group(2).strip()
                                if len(k_val) >= 12 and not any(fp in k_val.lower() for fp in FALSE_POSITIVE_SUBSTRINGS):
                                    redacted = redact_secret(k_val)
                                    key_id = f"{rel_path}:{redacted}"
                                    if key_id not in seen_redacted:
                                        seen_redacted.add(key_id)
                                        findings.append(
                                            self.create_finding(
                                                file_path=rel_path,
                                                line=line_idx,
                                                evidence=f"Suspicious credential key '{k_name}': {redacted}",
                                                custom_severity="High",
                                                custom_title=f"Credential String Resource '{k_name}'",
                                            )
                                        )
                                        if len(findings) >= 20:
                                            return findings

                        # Secondary Shannon entropy check on long continuous tokens in smali/assets
                        if file_path.suffix in (".smali", ".json", ".properties", ".txt"):
                            tokens = re.findall(r'[A-Za-z0-9_\-\.+=/]{20,}', line)
                            for token in tokens:
                                if any(fp in token.lower() for fp in FALSE_POSITIVE_SUBSTRINGS):
                                    continue
                                entropy = calculate_shannon_entropy(token)
                                if entropy >= entropy_threshold:
                                    redacted = redact_secret(token)
                                    key_id = f"{rel_path}:{redacted}"
                                    if key_id not in seen_redacted:
                                        seen_redacted.add(key_id)
                                        findings.append(
                                            self.create_finding(
                                                file_path=rel_path,
                                                line=line_idx,
                                                evidence=f"High entropy token (H={entropy:.2f}): {redacted}",
                                                custom_severity="Medium",
                                                custom_title="High-Entropy Secret Candidate",
                                            )
                                        )
                                        if len(findings) >= 20:
                                            return findings
            except Exception:
                continue

        return findings
