"""Tests for AuditEngine and AuditReporter."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from scanner.engine import AuditEngine, AuditReport
from scanner.manifest import parse_manifest
from scanner.reporter import AuditReporter
from scanner.rules.base import Rule, RuleContext, Finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def engine():
    return AuditEngine()


@pytest.fixture
def reporter():
    return AuditReporter()


def test_engine_secure_manifest(engine):
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_secure.xml")
    report = engine.run_scan(manifest, scan_id="test-secure-01")

    assert report.scan_id == "test-secure-01"
    assert report.package_name == "com.example.secureapp"
    assert report.min_sdk == 26
    assert report.target_sdk == 34
    # No high findings in secure manifest
    assert report.high_count == 0


def test_engine_insecure_manifest(engine):
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_insecure.xml")
    report = engine.run_scan(manifest, scan_id="test-insecure-01")

    assert report.package_name == "com.example.vulnerableapp"
    assert report.high_count > 0  # debuggable, provider without perm, meta-data secrets, cleartext
    assert report.medium_count > 0  # allowBackup, targetSdk, exported components
    assert report.low_count > 0  # minSdk, dangerous permissions
    assert report.overall_risk == "High"

    # Verify findings are sorted by severity: High > Medium > Low
    severities = [f.severity for f in report.findings]
    high_indices = [i for i, s in enumerate(severities) if s == "High"]
    med_indices = [i for i, s in enumerate(severities) if s == "Medium"]
    low_indices = [i for i, s in enumerate(severities) if s == "Low"]

    if high_indices and med_indices:
        assert max(high_indices) < min(med_indices)
    if med_indices and low_indices:
        assert max(med_indices) < min(low_indices)


def test_engine_rule_exception_isolation(engine):
    """Ensure that an unhandled exception in one rule does not abort the audit."""
    class FailingRule(Rule):
        id = "BUGGY-001"
        def check(self, context: RuleContext):
            raise RuntimeError("Deliberate rule fault for isolation testing")

    # Inject the failing rule into engine's rule list
    engine.rules.insert(0, FailingRule({"title": "Buggy Rule", "severity": "High"}))

    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_secure.xml")
    report = engine.run_scan(manifest, scan_id="test-fault-01")

    # Verify the scan completed
    assert report.scan_id == "test-fault-01"
    # Verify the error was recorded in rule_errors
    assert any(err.rule_id == "BUGGY-001" for err in report.rule_errors)
    assert any("Deliberate rule fault" in err.error_message for err in report.rule_errors)


def test_engine_overall_risk_logic():
    # Helper to test risk calculation
    engine = AuditEngine()
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_secure.xml")

    # Mock rules that produce specific findings
    class MockHighRule(Rule):
        id = "MOCK-HIGH"
        def check(self, context):
            return [self.create_finding(file_path="f", evidence="e", custom_severity="High")]

    class MockMedRule(Rule):
        id = "MOCK-MED"
        def check(self, context):
            return [self.create_finding(file_path="f", evidence="e", custom_severity="Medium")]

    # High presence -> High
    engine.rules = [MockHighRule(), MockMedRule()]
    rep = engine.run_scan(manifest)
    assert rep.overall_risk == "High"

    # Medium only -> Medium
    engine.rules = [MockMedRule()]
    rep = engine.run_scan(manifest)
    assert rep.overall_risk == "Medium"

    # No findings -> Low
    engine.rules = []
    rep = engine.run_scan(manifest)
    assert rep.overall_risk == "Low"


def test_reporter_render_html(engine, reporter, tmp_path):
    manifest = parse_manifest(FIXTURES_DIR / "AndroidManifest_insecure.xml")
    report = engine.run_scan(manifest, scan_id="test-render-01")

    # Standard render
    html = reporter.render_report_html(report, standalone=False)
    assert "<title>Security Audit Report - com.example.vulnerableapp</title>" in html
    assert "Overall Risk: High" in html
    assert "Concrete Defensive Remediation" in html
    assert "Audit Limitations & Defensive Scope" in html

    # Standalone render (embeds CSS)
    html_standalone = reporter.render_report_html(report, standalone=True)
    assert "<style>" in html_standalone
    assert "--bg-primary: #0f172a;" in html_standalone

    # Save to file
    out_file = tmp_path / "report.html"
    saved_path = reporter.save_report_html(report, out_file, standalone=True)
    assert saved_path.is_file()
    assert saved_path.stat().st_size > 0
