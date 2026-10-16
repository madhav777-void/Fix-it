"""Network security audit rules (NET-001 through NET-005)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.rules.base import Rule, Finding, RuleContext

XML_NS_EXCLUSIONS = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://xml.org",
    "http://schemas.microsoft.com",
)


def _find_network_security_config_file(context: RuleContext) -> Optional[Path]:
    """Locate the network security config XML in the decoded APK directory if present."""
    if not context.decoded_dir or not context.decoded_dir.is_dir():
        return None

    # Check manifest attribute e.g. @xml/network_security_config
    nsc_attr = context.manifest.application.network_security_config
    if nsc_attr:
        # Extract filename (e.g. "network_security_config")
        base_name = nsc_attr.split("/")[-1].replace("@xml/", "")
        candidate = context.decoded_dir / "res" / "xml" / f"{base_name}.xml"
        if candidate.is_file():
            return candidate

    # Fallback to search any network_security_config*.xml in res/xml
    res_xml = context.decoded_dir / "res" / "xml"
    if res_xml.is_dir():
        for p in res_xml.glob("*network_security_config*.xml"):
            if p.is_file():
                return p

    return None


def _parse_xml_safely(path: Path) -> Optional[ET.Element]:
    """Safely parse XML file returning root element or None."""
    try:
        return ET.parse(path).getroot()
    except Exception:
        return None


class RuleNetworkUsesCleartextTraffic(Rule):
    """NET-001: usesCleartextTraffic='true' in application."""
    id = "NET-001"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if context.manifest.application.uses_cleartext_traffic is True:
            findings.append(
                self.create_finding(
                    file_path="AndroidManifest.xml",
                    evidence='<application android:usesCleartextTraffic="true">',
                )
            )
        return findings


class RuleNetworkConfigCleartext(Rule):
    """NET-002: network_security_config present but permits cleartext traffic."""
    id = "NET-002"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        nsc_path = _find_network_security_config_file(context)
        if not nsc_path:
            return findings

        root = _parse_xml_safely(nsc_path)
        if root is None:
            return findings

        rel_path = str(nsc_path.relative_to(context.decoded_dir)) if context.decoded_dir else nsc_path.name

        # Check <base-config cleartextTrafficPermitted="true">
        base_config = root.find("base-config")
        if base_config is not None:
            perm = base_config.attrib.get("cleartextTrafficPermitted", "").lower()
            if perm == "true":
                findings.append(
                    self.create_finding(
                        file_path=rel_path,
                        evidence='<base-config cleartextTrafficPermitted="true">',
                        custom_title="Network Security Config: Base Config Permits Cleartext",
                    )
                )

        # Check <domain-config cleartextTrafficPermitted="true">
        for domain_cfg in root.findall(".//domain-config"):
            perm = domain_cfg.attrib.get("cleartextTrafficPermitted", "").lower()
            if perm == "true":
                domains = [d.text.strip() for d in domain_cfg.findall("domain") if d.text]
                domain_str = ", ".join(domains) if domains else "specified domain"
                findings.append(
                    self.create_finding(
                        file_path=rel_path,
                        evidence=f'<domain-config cleartextTrafficPermitted="true"> for: {domain_str}',
                        custom_title=f"Network Security Config: Domain Config Permits Cleartext ({domain_str})",
                    )
                )

        return findings


class RuleNetworkHttpUrls(Rule):
    """NET-003: no network_security_config and app uses HTTP URLs."""
    id = "NET-003"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []

        # Only check if network_security_config is missing
        nsc_path = _find_network_security_config_file(context)
        if nsc_path or context.manifest.application.network_security_config:
            return findings

        if not context.decoded_dir or not context.decoded_dir.is_dir():
            return findings

        http_regex = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        found_urls: List[Tuple[str, str, int]] = []  # (url, rel_path, line_no)

        # Search res/values/*.xml and smali/**/*.smali
        search_dirs = [context.decoded_dir / "res" / "values"]
        search_dirs.extend(context.decoded_dir.glob("smali*"))

        for sdir in search_dirs:
            if not sdir.is_dir():
                continue
            for file_path in sdir.rglob("*"):
                if not file_path.is_file():
                    continue
                if not (file_path.suffix == ".xml" or file_path.suffix == ".smali"):
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_idx, line in enumerate(f, start=1):
                            matches = http_regex.findall(line)
                            for match in matches:
                                match_lower = match.lower()
                                if match_lower.startswith("http://") and not any(match_lower.startswith(ex) for ex in XML_NS_EXCLUSIONS):
                                    rel = str(file_path.relative_to(context.decoded_dir))
                                    found_urls.append((match, rel, line_idx))
                                    if len(found_urls) >= 5:  # Limit finding count
                                        break
                            if len(found_urls) >= 5:
                                break
                except Exception:
                    continue
                if len(found_urls) >= 5:
                    break

        for url, rel_path, line_no in found_urls:
            findings.append(
                self.create_finding(
                    file_path=rel_path,
                    line=line_no,
                    evidence=f"Plaintext HTTP URL endpoint found: {url}",
                )
            )

        return findings


class RuleNetworkCertificatePinning(Rule):
    """NET-004: no certificate pinning config found (informational)."""
    id = "NET-004"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        nsc_path = _find_network_security_config_file(context)

        has_pinning = False
        if nsc_path:
            root = _parse_xml_safely(nsc_path)
            if root is not None and root.find(".//pin-set") is not None:
                has_pinning = True

        if not has_pinning:
            evidence = (
                "No <pin-set> element configured in network security configuration."
                if nsc_path
                else "No network_security_config.xml configured in application."
            )
            findings.append(
                self.create_finding(
                    file_path=str(nsc_path.name) if nsc_path else "AndroidManifest.xml",
                    evidence=evidence,
                )
            )

        return findings


class RuleNetworkUserCertificates(Rule):
    """NET-005: user CA trust anchors allowed in release configuration."""
    id = "NET-005"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        nsc_path = _find_network_security_config_file(context)
        if not nsc_path:
            return findings

        root = _parse_xml_safely(nsc_path)
        if root is None:
            return findings

        rel_path = str(nsc_path.relative_to(context.decoded_dir)) if context.decoded_dir else nsc_path.name

        # Inspect non-debug trust-anchors: base-config and domain-config
        for parent_tag in ("base-config", "domain-config"):
            for section in root.findall(f".//{parent_tag}"):
                for cert in section.findall(".//trust-anchors/certificates"):
                    src = cert.attrib.get("src", "").lower()
                    if src == "user":
                        findings.append(
                            self.create_finding(
                                file_path=rel_path,
                                evidence=f'<{parent_tag}> allows user CA trust: <certificates src="user" />',
                                custom_title=f"User CA Trust Anchor in Release <{parent_tag}>",
                            )
                        )

        return findings
