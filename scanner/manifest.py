"""Android manifest parsing and typed data representations."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _android_attr(elem: ET.Element, name: str) -> Optional[str]:
    """Extract an attribute from an ElementTree element, checking Android namespace first."""
    val = elem.attrib.get(f"{{{ANDROID_NS}}}{name}")
    if val is not None:
        return val
    return elem.attrib.get(name)


def _parse_bool(val: Optional[str]) -> Optional[bool]:
    """Convert XML attribute string to boolean if applicable."""
    if val is None:
        return None
    val_lower = val.strip().lower()
    if val_lower in ("true", "1"):
        return True
    if val_lower in ("false", "0"):
        return False
    return None


def _parse_int(val: Optional[str]) -> Optional[int]:
    """Convert XML attribute string to integer safely."""
    if val is None:
        return None
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return None


@dataclass
class MetaData:
    """Represents a <meta-data> element."""
    name: str
    value: Optional[str] = None
    resource: Optional[str] = None


@dataclass
class ComponentData:
    """Represents an Android application component (activity, service, receiver, provider)."""
    component_type: str  # 'activity', 'service', 'receiver', 'provider'
    name: str
    explicit_exported: Optional[bool]
    effective_exported: bool
    has_intent_filter: bool
    permission: Optional[str] = None
    read_permission: Optional[str] = None  # provider only
    write_permission: Optional[str] = None  # provider only
    meta_data: List[MetaData] = field(default_factory=list)


@dataclass
class ApplicationData:
    """Represents the <application> element and its core security flags."""
    name: Optional[str] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None  # Android default is True if omitted
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    full_backup_content: Optional[str] = None
    data_extraction_rules: Optional[str] = None
    meta_data: List[MetaData] = field(default_factory=list)


@dataclass
class ManifestData:
    """Structured representation of AndroidManifest.xml."""
    package_name: str
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk_version: Optional[int] = None
    target_sdk_version: Optional[int] = None
    application: ApplicationData = field(default_factory=ApplicationData)
    activities: List[ComponentData] = field(default_factory=list)
    services: List[ComponentData] = field(default_factory=list)
    receivers: List[ComponentData] = field(default_factory=list)
    providers: List[ComponentData] = field(default_factory=list)
    uses_permissions: List[str] = field(default_factory=list)
    app_meta_data: List[MetaData] = field(default_factory=list)
    raw_xml_path: Optional[Path] = None

    @property
    def all_components(self) -> List[ComponentData]:
        """Return all declared components combined."""
        return self.activities + self.services + self.receivers + self.providers


def compute_effective_exported(
    explicit: Optional[bool],
    has_intent_filter: bool,
    target_sdk: Optional[int],
    component_type: str,
) -> bool:
    """
    Model Android's exported resolution logic:
    1. If android:exported is explicitly declared, that value always wins.
    2. If NOT declared:
       - In Android 12 (API 31+), declaration is mandatory for components with intent filters.
         If omitted on API 31+, modern tools/runtimes default to false or reject the build.
       - In Android < 31 (legacy targets):
         - If component has >= 1 intent-filter, it defaults to exported=True.
         - If no intent-filter, it defaults to exported=False.
       - ContentProvider: Prior to API 17, providers were exported=True by default even without intent filters.
    """
    if explicit is not None:
        return explicit

    # In modern Android 12+ (targetSdkVersion >= 31)
    if target_sdk is not None and target_sdk >= 31:
        return False

    # For legacy targetSdk (< 31 or unknown):
    if has_intent_filter:
        return True

    # ContentProvider legacy behavior on older targets (API < 17)
    if component_type == "provider" and target_sdk is not None and target_sdk < 17:
        return True

    return False


def parse_manifest(source: Union[str, Path, bytes, ET.Element]) -> ManifestData:
    """
    Parse an AndroidManifest.xml from a file path, XML string, XML bytes, or parsed Element.
    """
    if isinstance(source, ET.Element):
        root = source
        file_path = None
    elif isinstance(source, (str, Path)) and not str(source).strip().startswith("<"):
        file_path = Path(source)
        tree = ET.parse(file_path)
        root = tree.getroot()
    else:
        # String or bytes content
        raw = source if isinstance(source, (bytes, bytearray)) else str(source).encode("utf-8")
        root = ET.fromstring(raw)
        file_path = None

    package_name = root.attrib.get("package") or _android_attr(root, "package") or ""
    version_code = _parse_int(_android_attr(root, "versionCode"))
    version_name = _android_attr(root, "versionName")

    # Parse <uses-sdk>
    min_sdk = None
    target_sdk = None
    uses_sdk_elem = root.find("uses-sdk")
    if uses_sdk_elem is not None:
        min_sdk = _parse_int(_android_attr(uses_sdk_elem, "minSdkVersion"))
        target_sdk = _parse_int(_android_attr(uses_sdk_elem, "targetSdkVersion"))

    # Parse <uses-permission>
    permissions: List[str] = []
    for perm_elem in root.findall("uses-permission"):
        p_name = _android_attr(perm_elem, "name")
        if p_name:
            permissions.append(p_name)

    # Parse <application>
    app_data = ApplicationData()
    app_elem = root.find("application")
    activities: List[ComponentData] = []
    services: List[ComponentData] = []
    receivers: List[ComponentData] = []
    providers: List[ComponentData] = []
    app_meta_data: List[MetaData] = []

    if app_elem is not None:
        app_data.name = _android_attr(app_elem, "name")
        app_data.debuggable = _parse_bool(_android_attr(app_elem, "debuggable"))
        app_data.allow_backup = _parse_bool(_android_attr(app_elem, "allowBackup"))
        app_data.uses_cleartext_traffic = _parse_bool(_android_attr(app_elem, "usesCleartextTraffic"))
        app_data.network_security_config = _android_attr(app_elem, "networkSecurityConfig")
        app_data.full_backup_content = _android_attr(app_elem, "fullBackupContent")
        app_data.data_extraction_rules = _android_attr(app_elem, "dataExtractionRules")

        # Application-level meta-data
        for meta_elem in app_elem.findall("meta-data"):
            m_name = _android_attr(meta_elem, "name") or ""
            m_val = _android_attr(meta_elem, "value")
            m_res = _android_attr(meta_elem, "resource")
            meta = MetaData(name=m_name, value=m_val, resource=m_res)
            app_meta_data.append(meta)
            app_data.meta_data.append(meta)

        # Helper to parse components
        def _parse_component(elem: ET.Element, comp_type: str) -> ComponentData:
            c_name = _android_attr(elem, "name") or ""
            explicit_exp = _parse_bool(_android_attr(elem, "exported"))
            has_intent_filter = elem.find("intent-filter") is not None
            effective_exp = compute_effective_exported(
                explicit=explicit_exp,
                has_intent_filter=has_intent_filter,
                target_sdk=target_sdk,
                component_type=comp_type,
            )
            perm = _android_attr(elem, "permission")
            read_perm = _android_attr(elem, "readPermission")
            write_perm = _android_attr(elem, "writePermission")

            comp_meta: List[MetaData] = []
            for m in elem.findall("meta-data"):
                mn = _android_attr(m, "name") or ""
                mv = _android_attr(m, "value")
                mr = _android_attr(m, "resource")
                comp_meta.append(MetaData(name=mn, value=mv, resource=mr))

            return ComponentData(
                component_type=comp_type,
                name=c_name,
                explicit_exported=explicit_exp,
                effective_exported=effective_exp,
                has_intent_filter=has_intent_filter,
                permission=perm,
                read_permission=read_perm,
                write_permission=write_perm,
                meta_data=comp_meta,
            )

        for act in app_elem.findall("activity"):
            activities.append(_parse_component(act, "activity"))
        for srv in app_elem.findall("service"):
            services.append(_parse_component(srv, "service"))
        for rec in app_elem.findall("receiver"):
            receivers.append(_parse_component(rec, "receiver"))
        for prov in app_elem.findall("provider"):
            providers.append(_parse_component(prov, "provider"))

    return ManifestData(
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        min_sdk_version=min_sdk,
        target_sdk_version=target_sdk,
        application=app_data,
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
        uses_permissions=permissions,
        app_meta_data=app_meta_data,
        raw_xml_path=file_path,
    )
