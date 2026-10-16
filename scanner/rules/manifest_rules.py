"""Manifest-based security audit rules."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pathlib import Path

from scanner.rules.base import Rule, Finding, RuleContext

MANIFEST_FILE = "AndroidManifest.xml"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Allows reading SMS messages containing OTPs or private text.",
    "android.permission.SEND_SMS": "Allows sending SMS messages without user interaction.",
    "android.permission.RECEIVE_SMS": "Allows intercepting incoming SMS messages.",
    "android.permission.RECORD_AUDIO": "Allows recording microphone audio without explicit UI prompts.",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Allows tracking device location in the background.",
    "android.permission.ACCESS_FINE_LOCATION": "Allows accessing precise GPS location data.",
    "android.permission.READ_CALL_LOG": "Allows reading user telephony call logs.",
    "android.permission.WRITE_CALL_LOG": "Allows modifying user telephony call logs.",
    "android.permission.READ_CONTACTS": "Allows reading full user address book / contacts.",
    "android.permission.WRITE_CONTACTS": "Allows modifying user address book / contacts.",
    "android.permission.CAMERA": "Allows accessing device camera to capture images or video.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows displaying overlays on top of other apps (tapjacking risk).",
}


class RuleManifestDebuggable(Rule):
    """MANIFEST-001: debuggable=true in application."""
    id = "MANIFEST-001"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        if context.manifest.application.debuggable is True:
            findings.append(
                self.create_finding(
                    file_path=MANIFEST_FILE,
                    evidence='<application android:debuggable="true">',
                )
            )
        return findings


class RuleManifestAllowBackup(Rule):
    """MANIFEST-002: allowBackup not set to false."""
    id = "MANIFEST-002"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        app = context.manifest.application
        # allow_backup defaults to True if omitted in Android
        if app.allow_backup is True or app.allow_backup is None:
            if app.allow_backup is None:
                evidence = 'android:allowBackup is omitted (Android defaults to "true")'
            else:
                evidence = '<application android:allowBackup="true">'

            # Mention if dataExtractionRules or fullBackupContent are present
            if app.data_extraction_rules or app.full_backup_content:
                evidence += f" (dataExtractionRules: {app.data_extraction_rules}, fullBackupContent: {app.full_backup_content})"

            findings.append(
                self.create_finding(
                    file_path=MANIFEST_FILE,
                    evidence=evidence,
                )
            )
        return findings


class RuleManifestExportedComponents(Rule):
    """MANIFEST-003: exported components without a permission guard."""
    id = "MANIFEST-003"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []

        # Check activities, services, receivers
        components = (
            context.manifest.activities +
            context.manifest.services +
            context.manifest.receivers
        )

        for comp in components:
            if not comp.effective_exported:
                continue

            # If it's an activity, check if it's the primary launcher
            # Note: The launcher activity must be exported to start the app from home screen
            # Flag non-launcher exported components or note launcher status
            if comp.permission:
                continue

            reason = "explicitly declared exported='true'" if comp.explicit_exported else "inferred exported=true from intent-filter on legacy targetSdk"
            evidence = f"<{comp.component_type} android:name='{comp.name}' is exported ({reason}) with no android:permission guard"

            findings.append(
                self.create_finding(
                    file_path=MANIFEST_FILE,
                    evidence=evidence,
                    custom_title=f"Exported {comp.component_type.capitalize()} '{comp.name}' Missing Permission Guard",
                )
            )

        return findings


class RuleManifestExportedProvider(Rule):
    """MANIFEST-004: ContentProvider exported with no readPermission/writePermission."""
    id = "MANIFEST-004"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        for prov in context.manifest.providers:
            if not prov.effective_exported:
                continue

            has_general_perm = bool(prov.permission)
            has_read_perm = bool(prov.read_permission)
            has_write_perm = bool(prov.write_permission)

            if not has_general_perm and not (has_read_perm and has_write_perm):
                missing = []
                if not has_general_perm and not has_read_perm:
                    missing.append("readPermission")
                if not has_general_perm and not has_write_perm:
                    missing.append("writePermission")

                evidence = (
                    f"<provider android:name='{prov.name}' android:exported='true'> "
                    f"missing {', '.join(missing)}"
                )
                findings.append(
                    self.create_finding(
                        file_path=MANIFEST_FILE,
                        evidence=evidence,
                        custom_title=f"Exported ContentProvider '{prov.name}' Unprotected",
                    )
                )

        return findings


class RuleManifestMinSdk(Rule):
    """MANIFEST-005: minSdkVersion below 24."""
    id = "MANIFEST-005"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        min_sdk = context.manifest.min_sdk_version
        recommended = context.settings.get("min_sdk_recommended", 24)

        if min_sdk is not None and min_sdk < recommended:
            evidence = f"<uses-sdk android:minSdkVersion='{min_sdk}'> (recommended threshold: >={recommended})"
            findings.append(
                self.create_finding(
                    file_path=MANIFEST_FILE,
                    evidence=evidence,
                )
            )
        return findings


class RuleManifestTargetSdk(Rule):
    """MANIFEST-006: targetSdkVersion below Google Play requirement."""
    id = "MANIFEST-006"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        target_sdk = context.manifest.target_sdk_version
        required = context.settings.get("current_target_sdk_requirement", 34)

        if target_sdk is not None and target_sdk < required:
            evidence = f"<uses-sdk android:targetSdkVersion='{target_sdk}'> (current Play Store requirement: >={required})"
            findings.append(
                self.create_finding(
                    file_path=MANIFEST_FILE,
                    evidence=evidence,
                )
            )
        return findings


class RuleManifestDangerousPermissions(Rule):
    """MANIFEST-007: requests dangerous permissions the app may not need."""
    id = "MANIFEST-007"

    def check(self, context: RuleContext) -> List[Finding]:
        findings: List[Finding] = []
        for perm in context.manifest.uses_permissions:
            if perm in DANGEROUS_PERMISSIONS:
                desc = DANGEROUS_PERMISSIONS[perm]
                evidence = f"Requested: {perm} - {desc}. Verify this is required."
                findings.append(
                    self.create_finding(
                        file_path=MANIFEST_FILE,
                        evidence=evidence,
                        custom_title=f"Dangerous Permission Requested: {perm.split('.')[-1]}",
                    )
                )
        return findings
