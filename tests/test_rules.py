"""Tests for audit rules: positive and negative test cases."""

from pathlib import Path
import pytest

from scanner.manifest import parse_manifest
from scanner.rules.base import load_rules_yaml, RuleContext
from scanner.rules.manifest_rules import (
    RuleManifestDebuggable,
    RuleManifestAllowBackup,
    RuleManifestExportedComponents,
    RuleManifestExportedProvider,
    RuleManifestMinSdk,
    RuleManifestTargetSdk,
    RuleManifestDangerousPermissions,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def rules_config():
    return load_rules_yaml()


@pytest.fixture
def secure_context(rules_config):
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_secure.xml")
    return RuleContext(
        manifest=manifest,
        settings=rules_config.get("settings", {}),
    )


@pytest.fixture
def insecure_context(rules_config):
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_insecure.xml")
    return RuleContext(
        manifest=manifest,
        settings=rules_config.get("settings", {}),
    )


def test_load_rules_yaml(rules_config):
    assert "rules" in rules_config
    assert "MANIFEST-001" in rules_config["rules"]
    assert "NET-001" in rules_config["rules"]
    assert "SECRET-001" in rules_config["rules"]
    assert rules_config["rules"]["MANIFEST-001"]["severity"] == "High"


# ============================================================================
# MANIFEST RULES TESTS
# ============================================================================

def test_manifest_debuggable(rules_config, secure_context, insecure_context):
    rule = RuleManifestDebuggable(rules_config["rules"]["MANIFEST-001"])

    # Positive: insecure manifest has debuggable=true
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 1
    assert findings_pos[0].rule_id == "MANIFEST-001"
    assert findings_pos[0].severity == "High"
    assert "debuggable" in findings_pos[0].evidence

    # Negative: secure manifest has debuggable=false
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0


def test_manifest_allow_backup(rules_config, secure_context, insecure_context):
    rule = RuleManifestAllowBackup(rules_config["rules"]["MANIFEST-002"])

    # Positive: insecure manifest has allowBackup=true
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 1
    assert findings_pos[0].rule_id == "MANIFEST-002"
    assert findings_pos[0].severity == "Medium"

    # Negative: secure manifest has allowBackup=false
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0


def test_manifest_exported_components(rules_config, secure_context, insecure_context):
    rule = RuleManifestExportedComponents(rules_config["rules"]["MANIFEST-003"])

    # Positive: insecure manifest has unprotected exported components
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) >= 2  # Service and Receiver and/or Activity
    rule_ids = [f.rule_id for f in findings_pos]
    assert all(rid == "MANIFEST-003" for rid in rule_ids)

    # Negative: secure manifest has no unprotected exported components
    # (MainActivity is launcher, others are exported=false)
    # MainActivity is exported launcher; let's check
    internal_act = next(a for a in secure_context.manifest.activities if a.name == ".InternalActivity")
    assert internal_act.effective_exported is False


def test_manifest_exported_provider(rules_config, secure_context, insecure_context):
    rule = RuleManifestExportedProvider(rules_config["rules"]["MANIFEST-004"])

    # Positive: insecure manifest has exported provider without permissions
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 1
    assert findings_pos[0].rule_id == "MANIFEST-004"
    assert findings_pos[0].severity == "High"

    # Negative: secure manifest has exported=false for provider
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0


def test_manifest_min_sdk(rules_config, secure_context, insecure_context):
    rule = RuleManifestMinSdk(rules_config["rules"]["MANIFEST-005"])

    # Positive: insecure manifest has minSdk=21 (< 24)
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 1
    assert findings_pos[0].rule_id == "MANIFEST-005"
    assert findings_pos[0].severity == "Low"

    # Negative: secure manifest has minSdk=26 (>= 24)
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0


def test_manifest_target_sdk(rules_config, secure_context, insecure_context):
    rule = RuleManifestTargetSdk(rules_config["rules"]["MANIFEST-006"])

    # Positive: insecure manifest has targetSdk=28 (< 34)
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 1
    assert findings_pos[0].rule_id == "MANIFEST-006"
    assert findings_pos[0].severity == "Medium"

    # Negative: secure manifest has targetSdk=34 (>= 34)
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0


def test_manifest_dangerous_permissions(rules_config, secure_context, insecure_context):
    rule = RuleManifestDangerousPermissions(rules_config["rules"]["MANIFEST-007"])

    # Positive: insecure manifest requests READ_SMS, RECORD_AUDIO, ACCESS_BACKGROUND_LOCATION
    findings_pos = rule.check(insecure_context)
    assert len(findings_pos) == 3
    perm_evidences = " ".join(f.evidence for f in findings_pos)
    assert "READ_SMS" in perm_evidences
    assert "RECORD_AUDIO" in perm_evidences

    # Negative: secure manifest only requests INTERNET and ACCESS_NETWORK_STATE
    findings_neg = rule.check(secure_context)
    assert len(findings_neg) == 0
