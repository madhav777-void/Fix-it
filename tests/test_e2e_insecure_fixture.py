"""End-to-end test validating the complete audit pipeline against the deliberately insecure fixture."""

import shutil
import zipfile
from pathlib import Path
import pytest

from scanner.engine import AuditEngine
from scanner.manifest import parse_manifest
from scanner.reporter import AuditReporter

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def insecure_apk_environment(tmp_path):
    """
    Constructs a complete simulated decoded APK structure containing the deliberately
    insecure manifest, insecure network config, hardcoded secrets, insecure storage,
    unobfuscated code, and debug v1-only certificate.
    """
    decoded_dir = tmp_path / "decoded_insecure_app"
    decoded_dir.mkdir(parents=True)

    # 1. Manifest
    insecure_manifest_path = FIXTURES_DIR / "AndroidManifest_insecure.xml"
    shutil.copyfile(str(insecure_manifest_path), str(decoded_dir / "AndroidManifest.xml"))

    # 2. Network security config in res/xml/
    res_xml = decoded_dir / "res" / "xml"
    res_xml.mkdir(parents=True)
    (res_xml / "network_security_config.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>""",
        encoding="utf-8",
    )

    # 3. Resources with plaintext HTTP and secrets in res/values/
    res_val = decoded_dir / "res" / "values"
    res_val.mkdir(parents=True)
    (res_val / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="api_endpoint">http://api.insecure-service.internal/v1</string>
    <string name="aws_key_id">AKIAIOSFODNN7EXAMPLE</string>
    <string name="google_maps_key">AIzaSyDx1234567890abcdefghijklmnopqrstuv</string>
</resources>""",
        encoding="utf-8",
    )

    # 4. Unobfuscated smali with storage flaws
    smali_dir = decoded_dir / "smali" / "com" / "example" / "vulnerableapp"
    smali_dir.mkdir(parents=True)
    (smali_dir / "UserDataManager.smali").write_text(
        """.class public Lcom/example/vulnerableapp/UserDataManager;
.super Ljava/lang/Object;

.method public saveUserData()V
    const-string v0, "user_password"
    invoke-virtual {p0, v0, 0x0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    sget v1, Landroid/content/Context;->MODE_WORLD_READABLE:I
    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    return-void
.end method
""",
        encoding="utf-8",
    )

    # 5. Build fake APK file signed with debug cert (v1 only, no v2 APK Sig Block)
    apk_path = tmp_path / "insecure_app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", (FIXTURES_DIR / "AndroidManifest_insecure.xml").read_bytes())
        zf.writestr("META-INF/CERT.RSA", b"Subject: CN=Android Debug, O=Android, C=US\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")

    return decoded_dir, apk_path


def test_full_engine_e2e_insecure_audit(insecure_apk_environment):
    decoded_dir, apk_path = insecure_apk_environment

    manifest = parse_manifest(decoded_dir / "AndroidManifest.xml")
    engine = AuditEngine()
    reporter = AuditReporter()

    report = engine.run_scan(
        manifest=manifest,
        decoded_dir=decoded_dir,
        apk_path=apk_path,
        scan_id="e2e-insecure-test-001",
        duration_seconds=1.25,
    )

    # 1. Verify Report Metadata
    assert report.scan_id == "e2e-insecure-test-001"
    assert report.package_name == "com.example.vulnerableapp"
    assert report.overall_risk == "High"
    assert report.high_count >= 5
    assert report.medium_count >= 3
    assert report.low_count >= 2
    assert report.total_count >= 10
    assert len(report.rule_errors) == 0

    # 2. Verify Presence of Rule Categories
    rule_ids = {f.rule_id for f in report.findings}

    # Manifest Rules
    assert "MANIFEST-001" in rule_ids  # debuggable
    assert "MANIFEST-002" in rule_ids  # allowBackup
    assert "MANIFEST-003" in rule_ids  # exported components
    assert "MANIFEST-004" in rule_ids  # exported provider
    assert "MANIFEST-005" in rule_ids  # minSdk < 24
    assert "MANIFEST-006" in rule_ids  # targetSdk < 34
    assert "MANIFEST-007" in rule_ids  # dangerous permissions

    # Network Rules
    assert "NET-001" in rule_ids  # usesCleartextTraffic=true
    assert "NET-002" in rule_ids  # cleartextTrafficPermitted in config
    assert "NET-004" in rule_ids  # missing pin-set
    assert "NET-005" in rule_ids  # user CA trust

    # Secret Rules
    assert "SECRET-001" in rule_ids  # hardcoded secrets

    # Storage Rules
    assert "STORAGE-001" in rule_ids  # unencrypted prefs
    assert "STORAGE-002" in rule_ids  # MODE_WORLD_READABLE
    assert "STORAGE-003" in rule_ids  # external storage

    # Build Rules
    assert "BUILD-001" in rule_ids  # unobfuscated code
    assert "BUILD-002" in rule_ids  # v1-only signing
    assert "BUILD-003" in rule_ids  # debug cert

    # 3. Verify Mandatory Redaction on all findings
    for finding in report.findings:
        assert finding.rule_id != ""
        assert finding.severity in ("High", "Medium", "Low")
        assert finding.title != ""
        assert finding.fix != ""
        assert finding.evidence != ""

        # Raw secrets must never appear unredacted
        assert "AIzaSyDx1234567890abcdefghijklmnopqrstuv" not in finding.evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in finding.evidence

    # 4. Verify HTML Generation (both interactive and standalone)
    html_interactive = reporter.render_report_html(report, standalone=False)
    assert "Overall Risk: High" in html_interactive
    assert "com.example.vulnerableapp" in html_interactive
    assert "MANIFEST-001" in html_interactive

    html_standalone = reporter.render_report_html(report, standalone=True)
    assert "<style>" in html_standalone
    assert "com.example.vulnerableapp" in html_standalone
    assert "Audit Limitations & Defensive Scope" in html_standalone
