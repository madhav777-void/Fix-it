# Contributing to APK Hardening Audit Tool

Thank you for your interest in contributing! This project is designed strictly as a **defensive developer-side static analysis tool** to help Android developers audit and harden their own applications.

---

## 🛡️ Core Contribution Principles

1. **Defensive Only**: Pull requests that add bypass tooling, tampering utilities, cracking routines, or offensive features will be rejected immediately.
2. **Privacy & Redaction**: Any rule detecting credentials, keys, or sensitive strings MUST enforce redaction (`[first 4]...[last 2]`) in evidence fields.
3. **Offline & Local**: The tool must remain 100% offline and local. No external network transmission of APK contents or metadata.

---

## 🛠️ Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd "Fix It"
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download `apktool.jar` (optional if already on system PATH):**
   ```bash
   python scripts/download_apktool.py
   ```

5. **Run the test suite:**
   ```bash
   python -m pytest
   ```

6. **Start the local server:**
   ```bash
   python app.py
   ```

---

## 🧪 Adding New Audit Rules

1. Define the rule metadata in `rules.yaml` (title, severity, category, description, fix, code_snippet, references).
2. Implement or extend the rule class under `scanner/rules/` inheriting from `Rule`.
3. Add corresponding unit tests under `tests/test_rules.py`.
4. Ensure all tests pass with `python -m pytest`.
