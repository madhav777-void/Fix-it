"""Tests for Flask web application routes and scanning workflow."""

import io
import shutil
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app import app, WORKSPACE_DIR
from scanner.decoder import DecodeResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def minimal_apk_stream():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
    buf.seek(0)
    return buf


def test_get_index(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Audit &amp; Harden Your Android App" in html or "Audit & Harden" in html
    assert "Ethical &amp; Permission Notice" in html or "Ethical & Permission" in html
    assert 'name="apk_file"' in html


def test_scan_no_file(client):
    response = client.post("/scan", data={})
    assert response.status_code == 400
    assert "No file part" in response.get_data(as_text=True)


def test_scan_invalid_extension(client):
    data = {"apk_file": (io.BytesIO(b"some content"), "malicious.exe")}
    response = client.post("/scan", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert "must have an .apk extension" in response.get_data(as_text=True).lower()


def test_scan_invalid_magic_bytes(client):
    data = {"apk_file": (io.BytesIO(b"NOT_A_ZIP_HEADER"), "test.apk")}
    response = client.post("/scan", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert "magic bytes" in response.get_data(as_text=True).lower()


def test_get_report_not_found(client):
    response = client.get("/report/non_existent_scan_id_99999")
    assert response.status_code == 404


def test_scan_and_view_report_workflow(client, minimal_apk_stream):
    """Test full scan pipeline with simulated apktool decode."""
    def mock_decode(apk_p, out_p, timeout_seconds=120):
        # Emulate apktool by creating decoded directory and copying insecure manifest fixture
        out_p.mkdir(parents=True, exist_ok=True)
        insecure_xml = FIXTURES_DIR / "AndroidManifest_insecure.xml"
        shutil.copyfile(str(insecure_xml), str(out_p / "AndroidManifest.xml"))
        return DecodeResult(success=True, output_dir=out_p, apk_path=apk_p)

    with patch("app.decode_apk", side_effect=mock_decode):
        data = {
            "apk_file": (minimal_apk_stream, "my_sample_test.apk"),
            "keep_artifacts": "true",
        }
        res = client.post("/scan", data=data, content_type="multipart/form-data")
        assert res.status_code == 302
        redirect_url = res.headers["Location"]
        assert "/report/" in redirect_url

        scan_id = redirect_url.split("/")[-1]

        # Fetch rendered report page
        rep_res = client.get(f"/report/{scan_id}")
        assert rep_res.status_code == 200
        rep_html = rep_res.get_data(as_text=True)
        assert "com.example.vulnerableapp" in rep_html
        assert "Overall Risk: High" in rep_html
        assert "MANIFEST-001" in rep_html
        assert "Download Standalone HTML" in rep_html

        # Test download standalone report
        dl_res = client.get(f"/report/{scan_id}/download")
        assert dl_res.status_code == 200
        assert "text/html" in dl_res.headers["Content-Type"]
        dl_html = dl_res.get_data(as_text=True)
        assert "<style>" in dl_html
        assert "com.example.vulnerableapp" in dl_html

        # Cleanup workspace created for this scan
        shutil.rmtree(WORKSPACE_DIR / scan_id, ignore_errors=True)
