# Security Policy

## Reporting Security Issues

We take the security of this application seriously. Because this application processes untrusted file uploads (Android APK archives, XML manifests, bytecode), strict defensive controls are implemented to protect host systems.

If you discover a security vulnerability (such as a zip-slip flaw, path traversal, injection, or denial of service), please report it responsibly rather than opening a public issue.

### Built-in Defensive Controls
- **Zip-Slip Protection:** Path traversal prevention during archive decompression.
- **Upload Isolation:** Files are saved using random UUIDs and processed in isolated temporary directories.
- **Evidence Redaction:** High-entropy strings and credentials are automatically masked.
- **Local-Only Binding:** Default web server binds strictly to `127.0.0.1`.
- **Resource Limits:** Uploads are strictly capped (200MB default limit).

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |
