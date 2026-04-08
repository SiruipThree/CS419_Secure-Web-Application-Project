# Parts C And D Implementation Summary

This note captures the concrete controls implemented for course parts C and D.

## Part C: Input Validation And Injection Prevention

- Username, email, and password validation remain centralized in `secure_app/security.py`.
- Document titles are validated with required/non-empty checks, length limits, and control-character rejection.
- Uploads use whitelist validation for allowed extensions and expected MIME types.
- Uploaded file contents are checked against basic file signatures for `pdf`, `txt`, `doc`, `docx`, `png`, `jpg`, and `jpeg`.
- Unsafe filenames are normalized with `secure_filename`.
- Stored document paths are resolved against the configured document directory and rejected if they escape the base directory.
- Templates continue to rely on Jinja auto-escaping, and `sanitize_text()` is available for explicit escaping when needed.
- The implementation does not invoke shell commands for file handling, which avoids command-injection exposure in the upload/download path.

## Part D: Encryption

- Uploaded document payloads are encrypted at rest with `cryptography.Fernet`.
- The Fernet key is loaded from `secret.key` and generated automatically if it does not already exist.
- Encrypted payloads are stored under opaque generated names rather than user-supplied filenames.
- Download flows decrypt payloads in memory before returning the original file bytes to the client.
- `FORCE_HTTPS` can redirect insecure requests to HTTPS outside development.
- Optional `TLS_CERT_FILE` and `TLS_KEY_FILE` environment variables allow local TLS startup with Flask.
- HSTS is added only on secure requests.

## Audit And Evidence

- Upload and download events are written to structured log files and also appended to `data/audit.json`.
- Automated tests cover invalid file extensions, content-signature mismatch, encrypted-at-rest behavior, download decryption, HTTPS redirects, HSTS, and upload-size rejection.

## Residual Limitations

- File inspection is signature-based and does not use a malware scanner.
- Key rotation is not implemented yet; the current design manages a single generated Fernet key.
- HTTPS enforcement is application-level and still depends on TLS termination being available in the deployment environment.
