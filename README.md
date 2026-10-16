# APK Hardening Audit Tool (Defensive Developer-Side Scanner)

A local, defensive static analysis web application for Android developers to audit their own APKs (or authorized open-source builds). The tool automatically decompiles and inspects resources, configuration files, and bytecode to identify security weaknesses, flagging each finding with severity ratings, risk descriptions, and actionable remediation snippets (featuring concrete Gradle and AndroidManifest.xml code).

---

## 🛡️ Ethical & Defensive Use Statement

This tool is strictly built for defensive software engineering and hardening:
- **Zero Tampering:** It does **NOT** patch, repackage, re-sign, or modify APKs to bypass platform or application protections.
- **Zero Bypass Tooling:** It does **NOT** provide runtime hooking, dynamic instrumentation, root/emulator-detection bypass, or license-check bypass.
- **Strict Confidentiality & Redaction:** Discovered secrets and credentials are **NEVER** extracted or printed in full. Only a redacted preview (`[first 4]...[last 2]`, e.g., `AIza...9Z`) is shown in reports, logs, and interfaces.
- **100% Local Execution:** It makes **NO outbound network requests** with APK contents or metadata. All analysis runs entirely on `localhost:5000`.

> **Ethical Notice:** Only upload APKs that you personally own or have explicit, documented authorization to audit.

---

## 📋 Features & Rules Catalog

All rule metadata, descriptions, remediation instructions, and official links are configured declaratively in [`rules.yaml`](file:///c:/Users/Madhav%20Sharma/OneDrive/Desktop/Fix%20It/rules.yaml).

### 1. Manifest Security (`scanner/rules/manifest_rules.py`)
- **`MANIFEST-001` (High):** `android:debuggable="true"` detected in `<application>`. Allows arbitrary code execution and memory extraction via ADB.
- **`MANIFEST-002` (Medium):** `android:allowBackup` is omitted or set to `true`. Enables unauthorized data extraction via `adb backup`.
- **`MANIFEST-003` (Medium):** Exported Activities, Services, or Receivers without `android:permission` guards. Models Android 12 (`targetSdkVersion >= 31`) vs legacy exported defaults.
- **`MANIFEST-004` (High):** Exported `ContentProvider` missing `readPermission` and `writePermission`.
- **`MANIFEST-005` (Low):** `minSdkVersion` is below 24 (lacks default Network Security Config and modern platform defenses).
- **`MANIFEST-006` (Medium):** `targetSdkVersion` is below the current Google Play requirement (configurable in `rules.yaml`).
- **`MANIFEST-007` (Low):** Flagged high-risk dangerous permissions (e.g. `READ_SMS`, `RECORD_AUDIO`, `ACCESS_BACKGROUND_LOCATION`) for manual verification.

### 2. Network Security (`scanner/rules/network_rules.py`)
- **`NET-001` (High):** `android:usesCleartextTraffic="true"` permits unencrypted HTTP communication.
- **`NET-002` (High):** `network_security_config.xml` explicitly permits cleartext traffic in `<base-config>` or `<domain-config>`.
- **`NET-003` (Medium):** Plaintext `http://` endpoint URLs identified in code/resources without a network security config.
- **`NET-004` (Low / Info):** No certificate `<pin-set>` configured for sensitive domains.
- **`NET-005` (Medium):** User-installed CA trust anchors (`<certificates src="user"/>`) allowed in release configuration.

### 3. Secret Detection & Redaction (`scanner/rules/secret_rules.py`)
- **`SECRET-001` (High / Medium):** Scans `res/values/*.xml`, `assets/`, smali bytecode, and manifest `<meta-data>` for:
  - Google API Keys (`AIza[0-9A-Za-z\-_]{35}`)
  - AWS Access Key IDs (`AKIA[0-9A-Z]{16}`)
  - JSON Web Tokens (JWT) / Bearer strings (`eyJ...`)
  - Key/Secret assignment patterns (`api_key`, `secret`, `token`, `password`)
  - Shannon entropy analysis (threshold $\ge 4.0$ on tokens of length $\ge 20$)
  - **Mandatory Redaction:** All output is masked to show only the first 4 and last 2 characters (e.g. `AKIA...LE`).

### 4. Storage Security (`scanner/rules/storage_rules.py`)
- **`STORAGE-001` (Medium):** Sensitive keys (e.g. `password`, `token`, `secret`) stored in unencrypted `SharedPreferences` without `EncryptedSharedPreferences`.
- **`STORAGE-002` (High):** Insecure file permission modes (`MODE_WORLD_READABLE` or `MODE_WORLD_WRITEABLE`).
- **`STORAGE-003` (Medium):** Sensitive data stored on external/shared storage (`getExternalStorageDirectory`, `WRITE_EXTERNAL_STORAGE`).

### 5. Build & Obfuscation Integrity (`scanner/rules/build_rules.py`)
- **`BUILD-001` (Medium):** No evidence of R8 / ProGuard minification or obfuscation in smali classes.
- **`BUILD-002` (Medium):** Outdated APK Signature Scheme v1-only detected (lacks APK Signature Scheme v2/v3 block).
- **`BUILD-003` (High):** Debug certificate signature detected (`CN=Android Debug`).

---

## 🛠️ Prerequisites & Setup

### 1. System Requirements
- Python 3.11+
- Java Runtime Environment (JRE 8+) for `apktool`

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install `apktool`

`apktool` is used via subprocess to decode resources and binary XML into human-readable format.

- **Windows:**
  - Using Chocolatey:
    ```cmd
    choco install apktool
    ```
  - Using Scoop:
    ```cmd
    scoop install apktool
    ```
  - Manual installation:
    1. Download the Windows wrapper script [`apktool.bat`](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat).
    2. Download the latest `apktool_*.jar` from [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool/releases) and rename it to `apktool.jar`.
    3. Move both files to a directory on your system `PATH` (e.g., `C:\Windows\System32` or `C:\Program Files\apktool`).
  - *Optional:* You can also set the `APKTOOL_CMD` or `APKTOOL_JAR` environment variable:
    ```cmd
    set APKTOOL_CMD=C:\path\to\apktool.bat
    ```

- **macOS:**
  ```bash
  brew install apktool
  ```

- **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt update && sudo apt install apktool
  ```

---

## 🚀 Running the Web Application

1. Start the Flask application:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```
3. Drag and drop your `.apk` file (maximum 200 MB).
4. Review the generated audit report:
   - Overall Risk rating badge (`High`, `Medium`, `Low`)
   - Severity breakdown metric cards
   - Filterable findings by severity
   - Expandable "Concrete Defensive Remediation" sections with code snippets and official references
   - Click **Download Standalone HTML** to export a completely self-contained offline report.

---

## 🧪 Running the Test Suite

The test suite runs with `pytest` and uses small, handmade fixtures without requiring any third-party APKs:

```bash
python -m pytest -v
```

All 49 unit and integration tests validate:
- Upload validation (size limits, `.apk` extension, `PK\x03\x04` magic bytes)
- TargetSDK-aware exported component resolution
- Positive and negative tests for all 18 rules
- Mandatory secret redaction
- Isolated rule exception handling
- Flask routes and standalone report generation
- Full end-to-end audit with the deliberately insecure test fixture

---

## ⚠️ Limitations

- **Static Analysis Only:** The scanner inspects manifest configurations, resource XMLs, and disassembled bytecode. It does not perform dynamic runtime tracing or symbolic execution.
- **Obfuscated Code:** Heavily obfuscated bytecode, dynamic reflection (`Class.forName`), or native JNI libraries (`.so`) may conceal certain endpoint strings or API calls.
- **False Positives / Negatives:** Static heuristics may occasionally flag dummy test tokens or miss custom-encrypted payloads. Developer verification is always recommended.
- **Professional Review:** Automated auditing tools provide baseline hygiene and defensive hardening guidance; they are not a substitute for an end-to-end architectural threat model or professional manual penetration test.
