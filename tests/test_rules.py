"""Tests for audit rules: positive and negative test cases for all rules."""

import io
import zipfile
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
from scanner.rules.network_rules import (
    RuleNetworkUsesCleartextTraffic,
    RuleNetworkConfigCleartext,
    RuleNetworkHttpUrls,
    RuleNetworkCertificatePinning,
    RuleNetworkUserCertificates,
)
from scanner.rules.secret_rules import (
    RuleHardcodedSecrets,
    redact_secret,
    calculate_shannon_entropy,
)
from scanner.rules.storage_rules import (
    RuleStorageUnencryptedPreferences,
    RuleStorageWorldModes,
    RuleStorageExternalUsage,
)
from scanner.rules.build_rules import (
    RuleBuildObfuscation,
    RuleBuildSigningScheme,
    RuleBuildDebugCertificate,
    APK_SIG_BLOCK_MAGIC,
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
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    assert pos[0].severity == "High"
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_manifest_allow_backup(rules_config, secure_context, insecure_context):
    rule = RuleManifestAllowBackup(rules_config["rules"]["MANIFEST-002"])
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_manifest_exported_components(rules_config, secure_context, insecure_context):
    rule = RuleManifestExportedComponents(rules_config["rules"]["MANIFEST-003"])
    pos = rule.check(insecure_context)
    assert len(pos) >= 2
    # Ensure MainActivity in secure context is NOT flagged if it has launcher filter
    internal_act = next(a for a in secure_context.manifest.activities if a.name == ".InternalActivity")
    assert internal_act.effective_exported is False


def test_manifest_exported_provider(rules_config, secure_context, insecure_context):
    rule = RuleManifestExportedProvider(rules_config["rules"]["MANIFEST-004"])
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_manifest_min_sdk(rules_config, secure_context, insecure_context):
    rule = RuleManifestMinSdk(rules_config["rules"]["MANIFEST-005"])
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_manifest_target_sdk(rules_config, secure_context, insecure_context):
    rule = RuleManifestTargetSdk(rules_config["rules"]["MANIFEST-006"])
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_manifest_dangerous_permissions(rules_config, secure_context, insecure_context):
    rule = RuleManifestDangerousPermissions(rules_config["rules"]["MANIFEST-007"])
    pos = rule.check(insecure_context)
    assert len(pos) == 3
    neg = rule.check(secure_context)
    assert len(neg) == 0


# ============================================================================
# NETWORK RULES TESTS
# ============================================================================

def test_network_uses_cleartext_traffic(rules_config, secure_context, insecure_context):
    rule = RuleNetworkUsesCleartextTraffic(rules_config["rules"]["NET-001"])
    pos = rule.check(insecure_context)
    assert len(pos) == 1
    neg = rule.check(secure_context)
    assert len(neg) == 0


def test_network_config_cleartext(tmp_path, rules_config, secure_context):
    rule = RuleNetworkConfigCleartext(rules_config["rules"]["NET-002"])

    # Positive: cleartextTrafficPermitted="true" in base-config
    decoded_pos = tmp_path / "decoded_pos"
    res_xml = decoded_pos / "res" / "xml"
    res_xml.mkdir(parents=True)
    (res_xml / "network_security_config.xml").write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>',
        encoding="utf-8",
    )
    ctx_pos = RuleContext(
        manifest=secure_context.manifest,
        decoded_dir=decoded_pos,
        settings=rules_config["settings"],
    )
    findings_pos = rule.check(ctx_pos)
    assert len(findings_pos) == 1
    assert findings_pos[0].severity == "High"

    # Negative: cleartextTrafficPermitted="false"
    decoded_neg = tmp_path / "decoded_neg"
    res_xml_neg = decoded_neg / "res" / "xml"
    res_xml_neg.mkdir(parents=True)
    (res_xml_neg / "network_security_config.xml").write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="false" /></network-security-config>',
        encoding="utf-8",
    )
    ctx_neg = RuleContext(
        manifest=secure_context.manifest,
        decoded_dir=decoded_neg,
        settings=rules_config["settings"],
    )
    findings_neg = rule.check(ctx_neg)
    assert len(findings_neg) == 0


def test_network_http_urls(tmp_path, rules_config, insecure_context, secure_context):
    rule = RuleNetworkHttpUrls(rules_config["rules"]["NET-003"])

    # Positive: No network security config and contains http:// endpoint
    decoded_pos = tmp_path / "decoded_http"
    res_val = decoded_pos / "res" / "values"
    res_val.mkdir(parents=True)
    (res_val / "strings.xml").write_text(
        '<resources><string name="api_url">http://insecure-api.example.com/v1</string></resources>',
        encoding="utf-8",
    )
    ctx_pos = RuleContext(
        manifest=insecure_context.manifest,  # No networkSecurityConfig
        decoded_dir=decoded_pos,
        settings=rules_config["settings"],
    )
    findings_pos = rule.check(ctx_pos)
    assert len(findings_pos) == 1
    assert "http://insecure-api.example.com/v1" in findings_pos[0].evidence

    # Negative: App with networkSecurityConfig or only https://
    (res_val / "strings.xml").write_text(
        '<resources><string name="api_url">https://secure.example.com</string></resources>',
        encoding="utf-8",
    )
    findings_neg = rule.check(ctx_pos)
    assert len(findings_neg) == 0


def test_network_certificate_pinning(tmp_path, rules_config, secure_context):
    rule = RuleNetworkCertificatePinning(rules_config["rules"]["NET-004"])

    # Positive: network config without pin-set
    decoded_pos = tmp_path / "decoded_no_pin"
    res_xml = decoded_pos / "res" / "xml"
    res_xml.mkdir(parents=True)
    (res_xml / "network_security_config.xml").write_text(
        '<network-security-config><base-config><trust-anchors><certificates src="system" /></trust-anchors></base-config></network-security-config>',
        encoding="utf-8",
    )
    ctx_pos = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_pos)
    assert len(rule.check(ctx_pos)) == 1

    # Negative: network config WITH pin-set
    decoded_neg = tmp_path / "decoded_pin"
    res_xml_neg = decoded_neg / "res" / "xml"
    res_xml_neg.mkdir(parents=True)
    (res_xml_neg / "network_security_config.xml").write_text(
        '<network-security-config><domain-config><domain>example.com</domain><pin-set><pin digest="SHA-256">abc=</pin></pin-set></domain-config></network-security-config>',
        encoding="utf-8",
    )
    ctx_neg = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_neg)
    assert len(rule.check(ctx_neg)) == 0


def test_network_user_certificates(tmp_path, rules_config, secure_context):
    rule = RuleNetworkUserCertificates(rules_config["rules"]["NET-005"])

    # Positive: <certificates src="user" /> in base-config
    decoded_pos = tmp_path / "decoded_user_ca"
    res_xml = decoded_pos / "res" / "xml"
    res_xml.mkdir(parents=True)
    (res_xml / "network_security_config.xml").write_text(
        '<network-security-config><base-config><trust-anchors><certificates src="user" /></trust-anchors></base-config></network-security-config>',
        encoding="utf-8",
    )
    ctx_pos = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_pos)
    assert len(rule.check(ctx_pos)) == 1

    # Negative: only in debug-overrides or system certs
    decoded_neg = tmp_path / "decoded_sys_ca"
    res_xml_neg = decoded_neg / "res" / "xml"
    res_xml_neg.mkdir(parents=True)
    (res_xml_neg / "network_security_config.xml").write_text(
        '<network-security-config><base-config><trust-anchors><certificates src="system" /></trust-anchors></base-config><debug-overrides><trust-anchors><certificates src="user" /></trust-anchors></debug-overrides></network-security-config>',
        encoding="utf-8",
    )
    ctx_neg = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_neg)
    assert len(rule.check(ctx_neg)) == 0


# ============================================================================
# SECRET RULES & REDACTION TESTS
# ============================================================================

def test_secret_redaction_helper():
    assert redact_secret("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q") == "AIza...6Q"
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA...LE"
    assert redact_secret("short") == "[REDACTED]"


def test_shannon_entropy():
    # Repetitive string should have low entropy
    low = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low < 1.0

    # High randomness string
    high = calculate_shannon_entropy("4N9kL@p!zQ8$mX3vW7#r")
    assert high > 3.8


def test_secret_detection_patterns_and_redaction(tmp_path, rules_config, insecure_context):
    rule = RuleHardcodedSecrets(rules_config["rules"]["SECRET-001"])

    # Insecure context has google_api_key and jwt in manifest meta-data
    manifest_findings = rule.check(insecure_context)
    assert len(manifest_findings) >= 1

    # Verify every finding has strictly redacted evidence
    for f in manifest_findings:
        assert "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q" not in f.evidence
        assert "AIza..." in f.evidence or "..." in f.evidence

    # Decoded values file test
    decoded_dir = tmp_path / "decoded_secrets"
    res_val = decoded_dir / "res" / "values"
    res_val.mkdir(parents=True)
    raw_secret = "AIzaSyB9999999999999999999999999999999Z"
    (res_val / "strings.xml").write_text(
        f'<resources><string name="maps_api_key">{raw_secret}</string></resources>',
        encoding="utf-8",
    )
    ctx = RuleContext(manifest=insecure_context.manifest, decoded_dir=decoded_dir)
    findings = rule.check(ctx)
    assert any("maps_api_key" in f.evidence or "AIza...9Z" in f.evidence for f in findings)
    # Ensure raw secret is never present in any finding attribute
    for f in findings:
        assert raw_secret not in f.evidence
        assert raw_secret not in f.title
        assert raw_secret not in f.description


# ============================================================================
# STORAGE RULES TESTS
# ============================================================================

def test_storage_unencrypted_preferences(tmp_path, rules_config, secure_context):
    rule = RuleStorageUnencryptedPreferences(rules_config["rules"]["STORAGE-001"])

    # Positive: smali has getSharedPreferences with user_password and no EncryptedSharedPreferences
    decoded_pos = tmp_path / "decoded_storage_pos"
    smali_dir = decoded_pos / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AuthHelper.smali").write_text(
        'const-string v0, "user_password"\ninvoke-virtual {p0, v0, 0x0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;\n',
        encoding="utf-8",
    )
    ctx_pos = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_pos)
    findings_pos = rule.check(ctx_pos)
    assert len(findings_pos) >= 1

    # Negative: smali uses EncryptedSharedPreferences
    (smali_dir / "AuthHelper.smali").write_text(
        'invoke-static {}, Landroidx/security/crypto/EncryptedSharedPreferences;->create(...)Landroid/content/SharedPreferences;\n',
        encoding="utf-8",
    )
    findings_neg = rule.check(ctx_pos)
    assert len(findings_neg) == 0


def test_storage_world_modes(tmp_path, rules_config, secure_context):
    rule = RuleStorageWorldModes(rules_config["rules"]["STORAGE-002"])

    # Positive: MODE_WORLD_READABLE in smali
    decoded_pos = tmp_path / "decoded_world_mode"
    smali_dir = decoded_pos / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "FileIO.smali").write_text('sget v0, Landroid/content/Context;->MODE_WORLD_READABLE:I\n', encoding="utf-8")
    ctx_pos = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_pos)
    assert len(rule.check(ctx_pos)) == 1

    # Negative: clean smali
    (smali_dir / "FileIO.smali").write_text('const/4 v0, 0x0\n', encoding="utf-8")
    assert len(rule.check(ctx_pos)) == 0


def test_storage_external_usage(tmp_path, rules_config, secure_context, insecure_context):
    rule = RuleStorageExternalUsage(rules_config["rules"]["STORAGE-003"])

    # Positive: smali calls getExternalStorageDirectory
    decoded_pos = tmp_path / "decoded_ext_storage"
    smali_dir = decoded_pos / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Exporter.smali").write_text('invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;\n', encoding="utf-8")
    ctx_pos = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_pos)
    assert len(rule.check(ctx_pos)) == 1

    # Negative: clean
    (smali_dir / "Exporter.smali").write_text('invoke-virtual {p0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;\n', encoding="utf-8")
    assert len(rule.check(ctx_pos)) == 0


# ============================================================================
# BUILD RULES TESTS
# ============================================================================

def test_build_obfuscation(tmp_path, rules_config, secure_context):
    rule = RuleBuildObfuscation(rules_config["rules"]["BUILD-001"])

    # Positive: smali has only long readable class names
    decoded_unobf = tmp_path / "decoded_unobf"
    s_dir = decoded_unobf / "smali" / "com" / "example" / "myapp"
    s_dir.mkdir(parents=True)
    (s_dir / "UserAuthenticationController.smali").write_text(".class public Lcom/example/myapp/UserAuthenticationController;", encoding="utf-8")
    ctx_unobf = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_unobf)
    assert len(rule.check(ctx_unobf)) == 1

    # Negative: smali has short single-letter obfuscated classes (e.g. a/b.smali)
    decoded_obf = tmp_path / "decoded_obf"
    s_obf = decoded_obf / "smali" / "a"
    s_obf.mkdir(parents=True)
    (s_obf / "b.smali").write_text(".class public La/b;", encoding="utf-8")
    ctx_obf = RuleContext(manifest=secure_context.manifest, decoded_dir=decoded_obf)
    assert len(rule.check(ctx_obf)) == 0


def test_build_signing_scheme(tmp_path, rules_config, secure_context):
    rule = RuleBuildSigningScheme(rules_config["rules"]["BUILD-002"])

    # Positive: v1-only APK (META-INF present, no v2 APK Sig Block 42)
    v1_apk = tmp_path / "v1_only.apk"
    with zipfile.ZipFile(v1_apk, "w") as zf:
        zf.writestr("META-INF/CERT.RSA", b"fake_rsa_content")
        zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
    ctx_v1 = RuleContext(manifest=secure_context.manifest, apk_path=v1_apk)
    findings_v1 = rule.check(ctx_v1)
    assert len(findings_v1) == 1
    assert findings_v1[0].rule_id == "BUILD-002"

    # Negative: APK containing v2/v3 signing block magic
    v2_apk = tmp_path / "v2_signed.apk"
    with zipfile.ZipFile(v2_apk, "w") as zf:
        zf.writestr("META-INF/CERT.RSA", b"fake_rsa_content")
        zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
    with open(v2_apk, "ab") as f:
        f.write(b"\x00" * 32 + APK_SIG_BLOCK_MAGIC + b"\x00" * 32)
    ctx_v2 = RuleContext(manifest=secure_context.manifest, apk_path=v2_apk)
    assert len(rule.check(ctx_v2)) == 0


def test_build_debug_certificate(tmp_path, rules_config, secure_context):
    rule = RuleBuildDebugCertificate(rules_config["rules"]["BUILD-003"])

    # Positive: Debug cert in META-INF
    debug_apk = tmp_path / "debug.apk"
    with zipfile.ZipFile(debug_apk, "w") as zf:
        zf.writestr("META-INF/CERT.RSA", b"Subject: CN=Android Debug, O=Android, C=US")
    ctx_dbg = RuleContext(manifest=secure_context.manifest, apk_path=debug_apk)
    findings_dbg = rule.check(ctx_dbg)
    assert len(findings_dbg) == 1
    assert findings_dbg[0].severity == "High"

    # Negative: Release cert
    rel_apk = tmp_path / "release.apk"
    with zipfile.ZipFile(rel_apk, "w") as zf:
        zf.writestr("META-INF/CERT.RSA", b"Subject: CN=Acme Corporation Release Key")
    ctx_rel = RuleContext(manifest=secure_context.manifest, apk_path=rel_apk)
    assert len(rule.check(ctx_rel)) == 0
