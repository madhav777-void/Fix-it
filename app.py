"""Flask entry point for APK Hardening Audit Tool."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for

from scanner.decoder import (
    cleanup_directory,
    decode_apk,
    save_upload,
    validate_apk_file,
    MAX_APK_SIZE_BYTES,
)
from scanner.engine import AuditEngine, AuditReport
from scanner.manifest import parse_manifest
from scanner.reporter import AuditReporter
from scanner.rules.base import Finding

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("apk_audit")

BASE_DIR = Path(__file__).resolve().parent

# Serverless/Vercel fallback for workspace path
custom_workspace = os.environ.get("WORKSPACE_DIR")
if custom_workspace:
    WORKSPACE_DIR = Path(custom_workspace)
elif os.environ.get("VERCEL") or not os.access(BASE_DIR, os.W_OK):
    WORKSPACE_DIR = Path(tempfile.gettempdir()) / "apk_audit_workspace"
else:
    WORKSPACE_DIR = BASE_DIR / "workspace"

try:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    WORKSPACE_DIR = Path(tempfile.gettempdir()) / "apk_audit_workspace"
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["SECRET_KEY"] = os.urandom(24).hex()
app.config["MAX_CONTENT_LENGTH"] = MAX_APK_SIZE_BYTES

# Global audit engine and reporter
engine = AuditEngine()
reporter = AuditReporter()


def _reconstruct_report(data: Dict[str, Any]) -> AuditReport:
    """Reconstruct an AuditReport dataclass from stored JSON data."""
    findings = [Finding(**f) for f in data.get("findings", [])]
    return AuditReport(
        scan_id=data["scan_id"],
        package_name=data["package_name"],
        version_name=data["version_name"],
        version_code=data.get("version_code"),
        min_sdk=data.get("min_sdk"),
        target_sdk=data.get("target_sdk"),
        scan_time=data["scan_time"],
        tool_version=data["tool_version"],
        overall_risk=data["overall_risk"],
        high_count=data["high_count"],
        medium_count=data["medium_count"],
        low_count=data["low_count"],
        total_count=data["total_count"],
        findings=findings,
        rule_errors=data.get("rule_errors", []),
        duration_seconds=data.get("duration_seconds", 0.0),
    )


@app.route("/", methods=["GET"])
def index():
    """Upload form with ethical use and permission notice."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """Validate uploaded APK, run decoding and rule evaluation, then redirect to report."""
    if "apk_file" not in request.files:
        return render_template("index.html", error="No file part in upload request."), 400

    file = request.files["apk_file"]
    if not file or not file.filename:
        return render_template("index.html", error="No APK file selected for upload."), 400

    # 1. Validation
    is_valid, err_msg = validate_apk_file(file.stream, original_filename=file.filename)
    if not is_valid:
        logger.warning(f"Rejected invalid upload: {err_msg}")
        return render_template("index.html", error=err_msg), 400

    keep_artifacts = request.form.get("keep_artifacts") in ("true", "1", "on")

    # 2. Setup workspace directory
    scan_id = uuid.uuid4().hex
    scan_dir = WORKSPACE_DIR / scan_id
    upload_dir = scan_dir / "upload"
    decoded_dir = scan_dir / "decoded"
    upload_dir.mkdir(parents=True, exist_ok=True)

    start_time = time.monotonic()

    try:
        # 3. Save file with safe UUID filename
        apk_path = save_upload(file.stream, upload_dir, original_filename=file.filename)
        logger.info(f"Saved uploaded APK to safe path: {apk_path.name} (scan_id={scan_id})")

        # 4. Run apktool decode
        logger.info(f"Decoding APK {scan_id} with apktool...")
        decode_res = decode_apk(apk_path, decoded_dir, timeout_seconds=120)

        if not decode_res.success:
            logger.error(f"Apktool decode failure for {scan_id}: {decode_res.error}")
            if not keep_artifacts:
                cleanup_directory(scan_dir)
            return render_template(
                "index.html",
                error=f"APK decoding failed: {decode_res.error}",
            ), 500

        # 5. Locate and parse AndroidManifest.xml
        manifest_file = decoded_dir / "AndroidManifest.xml"
        if not manifest_file.is_file():
            logger.error(f"AndroidManifest.xml missing after decode for {scan_id}")
            if not keep_artifacts:
                cleanup_directory(scan_dir)
            return render_template(
                "index.html",
                error="Decoded APK does not contain an AndroidManifest.xml file.",
            ), 500

        manifest = parse_manifest(manifest_file)

        # 6. Run audit engine
        duration = time.monotonic() - start_time
        logger.info(f"Running audit rules for {manifest.package_name}...")
        report = engine.run_scan(
            manifest=manifest,
            decoded_dir=decoded_dir,
            apk_path=apk_path,
            scan_id=scan_id,
            duration_seconds=duration,
        )

        # 7. Persist report JSON & Standalone HTML
        report_json_path = scan_dir / "report.json"
        report_json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

        standalone_html_path = scan_dir / "report.html"
        reporter.save_report_html(report, standalone_html_path, standalone=True)

        # 8. Cleanup decoded files if user did not request keeping artifacts
        if not keep_artifacts:
            cleanup_directory(decoded_dir)
            cleanup_directory(upload_dir)
            logger.info(f"Cleaned up temporary decoded artifacts for {scan_id}")

        return redirect(url_for("view_report", scan_id=scan_id))

    except Exception as e:
        logger.exception(f"Unexpected error during scan {scan_id}: {e}")
        if not keep_artifacts:
            cleanup_directory(scan_dir)
        return render_template("index.html", error=f"An unexpected scan error occurred: {str(e)}"), 500


@app.route("/report/<scan_id>", methods=["GET"])
def view_report(scan_id: str):
    """Render the generated audit report."""
    scan_dir = WORKSPACE_DIR / scan_id
    report_json_path = scan_dir / "report.json"

    if not report_json_path.is_file():
        abort(404, description=f"Audit report for scan ID '{scan_id}' not found.")

    try:
        report_data = json.loads(report_json_path.read_text(encoding="utf-8"))
        report = _reconstruct_report(report_data)
        return render_template("report.html", report=report, standalone=False)
    except Exception as e:
        logger.exception(f"Error loading report {scan_id}: {e}")
        abort(500, description="Error reading audit report.")


@app.route("/report/<scan_id>/download", methods=["GET"])
def download_report(scan_id: str):
    """Download the standalone self-contained HTML report."""
    scan_dir = WORKSPACE_DIR / scan_id
    standalone_path = scan_dir / "report.html"

    if not standalone_path.is_file():
        abort(404, description=f"Standalone report for scan ID '{scan_id}' not found.")

    # Get package name for filename if available
    download_name = f"apk_audit_report_{scan_id[:8]}.html"
    report_json_path = scan_dir / "report.json"
    if report_json_path.is_file():
        try:
            data = json.loads(report_json_path.read_text(encoding="utf-8"))
            pkg = data.get("package_name", "").replace("/", "_").replace("\\", "_")
            if pkg:
                download_name = f"apk_audit_{pkg}.html"
        except Exception:
            pass

    return send_file(
        str(standalone_path),
        as_attachment=True,
        download_name=download_name,
        mimetype="text/html",
    )


@app.route("/cleanup", methods=["POST"])
def cleanup_all():
    """Optional route to clean up all scan workspaces."""
    try:
        count = 0
        for item in WORKSPACE_DIR.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                count += 1
        return redirect(url_for("index"))
    except Exception as e:
        return render_template("index.html", error=f"Error cleaning workspace: {e}"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
