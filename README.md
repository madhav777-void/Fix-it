# APK Hardening Audit Tool (Defensive Developer-Side Scanner)

A local Python web application for Android developers to inspect and audit their own APKs (or authorized open-source builds) for security weaknesses, configuration flaws, and sensitive data leakage.

## Ethical & Defensive Scope
This tool is strictly defensive:
- It does **not** modify, repackage, or bypass security controls.
- It does **not** provide runtime hooking, instrumentation, or bypasses.
- Any detected secret values are strictly **redacted** (`[first 4]...[last 2]`).
- All scans occur strictly locally on `localhost:5000` without any external network calls.

## Quick Start
1. Ensure Python 3.11+ is installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the web server:
   ```bash
   python app.py
   ```
4. Access `http://localhost:5000` in your browser.
