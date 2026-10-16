"""Report generator: Renders findings and scan metadata to HTML via Jinja2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union
import jinja2

from scanner.engine import AuditReport


class AuditReporter:
    """Renders AuditReport objects into interactive and standalone HTML."""

    def __init__(self, templates_dir: Optional[Union[Path, str]] = None, static_dir: Optional[Union[Path, str]] = None):
        base_dir = Path(__file__).resolve().parent.parent
        self.templates_dir = Path(templates_dir) if templates_dir else base_dir / "templates"
        self.static_dir = Path(static_dir) if static_dir else base_dir / "static"

        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )

    def render_report_html(self, report: AuditReport, standalone: bool = False) -> str:
        """Render the report.html template for an AuditReport."""
        template = self.jinja_env.get_template("report.html")

        embedded_css = ""
        if standalone:
            css_file = self.static_dir / "style.css"
            if css_file.is_file():
                embedded_css = css_file.read_text(encoding="utf-8")

        return template.render(
            report=report,
            standalone=standalone,
            embedded_css=embedded_css,
        )

    def save_report_html(self, report: AuditReport, output_file: Union[Path, str], standalone: bool = True) -> Path:
        """Save rendered HTML report to a file."""
        out_p = Path(output_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        html_content = self.render_report_html(report, standalone=standalone)
        out_p.write_text(html_content, encoding="utf-8")
        return out_p
