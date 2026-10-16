"""Base classes for security rules, findings, and rule execution context."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from scanner.manifest import ManifestData

SEVERITY_ORDER = {"High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    """Represents an identified security or hardening finding."""
    rule_id: str
    severity: str  # 'High', 'Medium', 'Low'
    title: str
    file_path: str
    evidence: str
    fix: str
    description: str = ""
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    references: List[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class RuleContext:
    """Contextual data provided to each rule during audit."""
    manifest: ManifestData
    decoded_dir: Optional[Path] = None
    apk_path: Optional[Path] = None
    settings: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


def load_rules_yaml(yaml_path: Optional[Union[Path, str]] = None) -> Dict[str, Any]:
    """Load rule catalog and settings from rules.yaml."""
    if yaml_path is None:
        # Default to rules.yaml in project root
        yaml_path = Path(__file__).resolve().parent.parent.parent / "rules.yaml"

    p = Path(yaml_path)
    if not p.is_file():
        raise FileNotFoundError(f"Rules definition file not found: {p}")

    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return data


class Rule(ABC):
    """Abstract base class for all audit rules."""

    id: str = ""

    def __init__(self, metadata: Optional[Dict[str, Any]] = None):
        meta = metadata or {}
        self.title: str = meta.get("title", self.id)
        self.severity: str = meta.get("severity", "Medium")
        self.description: str = meta.get("description", "")
        self.fix: str = meta.get("fix", "")
        self.code_snippet: Optional[str] = meta.get("code_snippet")
        self.references: List[str] = meta.get("references", [])

    @abstractmethod
    def check(self, context: RuleContext) -> List[Finding]:
        """Perform the security check and return any findings."""
        raise NotImplementedError

    def create_finding(
        self,
        file_path: str,
        evidence: str,
        line: Optional[int] = None,
        custom_title: Optional[str] = None,
        custom_severity: Optional[str] = None,
        custom_description: Optional[str] = None,
        custom_fix: Optional[str] = None,
        custom_snippet: Optional[str] = None,
    ) -> Finding:
        """Helper to construct a Finding populated from rule metadata."""
        return Finding(
            rule_id=self.id,
            severity=custom_severity or self.severity,
            title=custom_title or self.title,
            description=custom_description or self.description,
            file_path=file_path,
            line=line,
            evidence=evidence,
            fix=custom_fix or self.fix,
            code_snippet=custom_snippet or self.code_snippet,
            references=list(self.references),
        )
