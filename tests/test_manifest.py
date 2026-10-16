"""Tests for AndroidManifest.xml parser."""

from pathlib import Path
import pytest

from scanner.manifest import (
    parse_manifest,
    compute_effective_exported,
    ManifestData,
    ComponentData,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_secure_manifest():
    path = FIXTURES_DIR / "AndroidManifest_secure.xml"
    manifest: ManifestData = parse_manifest(path)

    assert manifest.package_name == "com.example.secureapp"
    assert manifest.version_code == 100
    assert manifest.version_name == "1.0.0"
    assert manifest.min_sdk_version == 26
    assert manifest.target_sdk_version == 34

    # Application flags
    assert manifest.application.allow_backup is False
    assert manifest.application.debuggable is False
    assert manifest.application.uses_cleartext_traffic is False
    assert manifest.application.network_security_config == "@xml/network_security_config"

    # Permissions
    assert "android.permission.INTERNET" in manifest.uses_permissions
    assert "android.permission.ACCESS_NETWORK_STATE" in manifest.uses_permissions

    # Components
    assert len(manifest.activities) == 2
    main_act = next(a for a in manifest.activities if a.name == ".MainActivity")
    assert main_act.explicit_exported is True
    assert main_act.effective_exported is True
    assert main_act.has_intent_filter is True

    internal_act = next(a for a in manifest.activities if a.name == ".InternalActivity")
    assert internal_act.explicit_exported is False
    assert internal_act.effective_exported is False
    assert internal_act.has_intent_filter is False

    assert len(manifest.services) == 1
    assert manifest.services[0].effective_exported is False

    assert len(manifest.providers) == 1
    assert manifest.providers[0].effective_exported is False


def test_parse_insecure_manifest():
    path = FIXTURES_DIR / "AndroidManifest_insecure.xml"
    manifest: ManifestData = parse_manifest(path)

    assert manifest.package_name == "com.example.vulnerableapp"
    assert manifest.version_code == 1
    assert manifest.version_name == "0.0.1-beta"
    assert manifest.min_sdk_version == 21
    assert manifest.target_sdk_version == 28

    # Application flags
    assert manifest.application.allow_backup is True
    assert manifest.application.debuggable is True
    assert manifest.application.uses_cleartext_traffic is True

    # Permissions
    assert "android.permission.READ_SMS" in manifest.uses_permissions
    assert "android.permission.RECORD_AUDIO" in manifest.uses_permissions
    assert "android.permission.ACCESS_BACKGROUND_LOCATION" in manifest.uses_permissions

    # Component exported resolution for targetSdk=28 with intent filter:
    legacy_act = next(a for a in manifest.activities if a.name == ".LegacyShareActivity")
    assert legacy_act.explicit_exported is None
    assert legacy_act.has_intent_filter is True
    # Because targetSdk=28 (< 31) and has intent-filter, defaults to True
    assert legacy_act.effective_exported is True

    # Exported service without permission
    srv = next(s for s in manifest.services if s.name == ".UnprotectedCommandService")
    assert srv.effective_exported is True
    assert srv.permission is None

    # Exported provider without read/write permission
    prov = next(p for p in manifest.providers if p.name == ".VulnerableDataProvider")
    assert prov.effective_exported is True
    assert prov.read_permission is None
    assert prov.write_permission is None

    # Meta-data
    keys = {m.name: m.value for m in manifest.app_meta_data}
    assert "google_api_key" in keys
    assert "backend_jwt_secret" in keys


def test_effective_exported_matrix():
    # Explicit values always override
    assert compute_effective_exported(explicit=True, has_intent_filter=False, target_sdk=34, component_type="activity") is True
    assert compute_effective_exported(explicit=False, has_intent_filter=True, target_sdk=28, component_type="activity") is False

    # targetSdk >= 31 without explicit exported defaults to False
    assert compute_effective_exported(explicit=None, has_intent_filter=True, target_sdk=34, component_type="activity") is False
    assert compute_effective_exported(explicit=None, has_intent_filter=False, target_sdk=34, component_type="activity") is False

    # targetSdk < 31 with intent-filter defaults to True
    assert compute_effective_exported(explicit=None, has_intent_filter=True, target_sdk=30, component_type="activity") is True
    assert compute_effective_exported(explicit=None, has_intent_filter=True, target_sdk=26, component_type="service") is True

    # targetSdk < 31 without intent-filter defaults to False (except legacy provider)
    assert compute_effective_exported(explicit=None, has_intent_filter=False, target_sdk=28, component_type="activity") is False
    assert compute_effective_exported(explicit=None, has_intent_filter=False, target_sdk=16, component_type="provider") is True


def test_parse_manifest_from_string():
    xml = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.str">
        <application android:allowBackup="false" />
    </manifest>
    """
    manifest = parse_manifest(xml)
    assert manifest.package_name == "com.test.str"
    assert manifest.application.allow_backup is False
    assert manifest.min_sdk_version is None
