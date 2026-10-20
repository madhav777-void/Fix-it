"""Audit Engine: Orchestrates rule loading, execution, fault isolation, and finding aggregation."""

from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from scanner.manifest import ManifestData
from scanner.rules.base import Finding, Rule, RuleContext, load_rules_yaml, SEVERITY_ORDER
from scanner.rules.manifest_rules import (
    RuleManifestDebuggable,
    RuleManifestAllowBackup,
    RuleManifestExportedComponents,
    RuleManifestExportedProvider,
    RuleManifestMinSdk,
    RuleManifestTargetSdk,
    RuleManifestDangerousPermissions,
)
from scanner.rules.network_rules import (
    RuleNetworkUsesCleartextTraffic,
    RuleNetworkConfigCleartext,
    RuleNetworkHttpUrls,
    RuleNetworkCertificatePinning,
    RuleNetworkUserCertificates,
)
from scanner.rules.secret_rules import RuleHardcodedSecrets
from scanner.rules.storage_rules import (
    RuleStorageUnencryptedPreferences,
    RuleStorageWorldModes,
    RuleStorageExternalUsage,
)
from scanner.rules.build_rules import (
    RuleBuildObfuscation,
    RuleBuildSigningScheme,
    RuleBuildDebugCertificate,
)

logger = logging.getLogger(__name__)

TOOL_VERSION = "1.0.0"

ALL_RULE_CLASSES: List[Type[Rule]] = [
    # Manifest
    RuleManifestDebuggable,
    RuleManifestAllowBackup,
    RuleManifestExportedComponents,
    RuleManifestExportedProvider,
    RuleManifestMinSdk,
    RuleManifestTargetSdk,
    RuleManifestDangerousPermissions,
    # Network
    RuleNetworkUsesCleartextTraffic,
    RuleNetworkConfigCleartext,
    RuleNetworkHttpUrls,
    RuleNetworkCertificatePinning,
    RuleNetworkUserCertificates,
    # Secrets
    RuleHardcodedSecrets,
    # Storage
    RuleStorageUnencryptedPreferences,
    RuleStorageWorldModes,
    RuleStorageExternalUsage,
    # Build & Obfuscation
    RuleBuildObfuscation,
    RuleBuildSigningScheme,
    RuleBuildDebugCertificate,
]


@dataclass
class RuleError:
    """Records an isolated rule execution failure."""
    rule_id: str
    error_message: str


@dataclass
class AuditReport:
    """Comprehensive audit report produced by AuditEngine."""
    scan_id: str
    package_name: str
    version_name: str
    version_code: Optional[int]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    scan_time: str
    tool_version: str
    overall_risk: str  # 'High', 'Medium', 'Low'
    high_count: int
    medium_count: int
    low_count: int
    total_count: int
    findings: List[Finding] = field(default_factory=list)
    rule_errors: List[RuleError] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dict."""
        return {
            "scan_id": self.scan_id,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "scan_time": self.scan_time,
            "tool_version": self.tool_version,
            "overall_risk": self.overall_risk,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "total_count": self.total_count,
            "findings": [asdict(f) for f in self.findings],
            "rule_errors": [asdict(e) for e in self.rule_errors],
            "duration_seconds": self.duration_seconds,
        }


class AuditEngine:
    """Engine responsible for loading rules, executing checks, and collecting results."""

    def __init__(self, rules_yaml_path: Optional[Union[Path, str]] = None):
        self.config_data = load_rules_yaml(rules_yaml_path)
        self.settings = self.config_data.get("settings", {})
        self.rules_meta = self.config_data.get("rules", {})

        # Instantiate all registered rules
        self.rules: List[Rule] = []
        for rule_cls in ALL_RULE_CLASSES:
            meta = self.rules_meta.get(rule_cls.id, {})
            self.rules.append(rule_cls(meta))

    def run_scan(
        self,
        manifest: ManifestData,
        decoded_dir: Optional[Path] = None,
        apk_path: Optional[Path] = None,
        scan_id: str = "scan-001",
        duration_seconds: float = 0.0,
    ) -> AuditReport:
        """Run all security checks against the given APK context."""
        context = RuleContext(
            manifest=manifest,
            decoded_dir=decoded_dir,
            apk_path=apk_path,
            settings=self.settings,
        )

        all_findings: List[Finding] = []
        rule_errors: List[RuleError] = []

        # Execute each rule with isolated exception handling
        for rule in self.rules:
            try:
                rule_findings = rule.check(context)
                if rule_findings:
                    all_findings.extend(rule_findings)
            except Exception as e:
                logger.exception(f"Error executing rule {rule.id}: {e}")
                rule_errors.append(RuleError(rule_id=rule.id, error_message=str(e)))

        # Sort findings: High > Medium > Low, then by rule_id
        all_findings.sort(key=lambda f: (f.severity_rank, f.rule_id))

        # Calculate counts
        high_cnt = sum(1 for f in all_findings if f.severity == "High")
        med_cnt = sum(1 for f in all_findings if f.severity == "Medium")
        low_cnt = sum(1 for f in all_findings if f.severity == "Low")

        # Determine overall risk
        if high_cnt > 0:
            overall = "High"
        elif med_cnt > 0:
            overall = "Medium"
        else:
            overall = "Low"

        scan_time_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return AuditReport(
            scan_id=scan_id,
            package_name=manifest.package_name or "Unknown Application",
            version_name=manifest.version_name or "Unknown",
            version_code=manifest.version_code,
            min_sdk=manifest.min_sdk_version,
            target_sdk=manifest.target_sdk_version,
            scan_time=scan_time_str,
            tool_version=TOOL_VERSION,
            overall_risk=overall,
            high_count=high_cnt,
            medium_count=med_cnt,
            low_count=low_cnt,
            total_count=len(all_findings),
            findings=all_findings,
            rule_errors=rule_errors,
            duration_seconds=round(duration_seconds, 2),
        )
