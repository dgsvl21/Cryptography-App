# Cryptography App — Cryptographic Design

**Status:** Draft v0.1 — design only (not implemented)  
**Scope:** Offline desktop application, password-protected local file encryption and decryption.

## 1. Security objectives

- **Confidentiality:** File content should not be readable without the correct password-derived key.
- **Integrity and authenticity of encrypted data:** Unauthorized modifications to authenticated content must cause decryption to fail.
- **Safe file handling:** Original files must not be overwritten; unsuccessful operations must not publish a decrypted result.
- **Clear limitations:** This design does not guarantee secure erasure, hide file size or usage patterns, protect a compromised endpoint, or prevent rollback to an older valid encrypted file.

## 2. Selected cryptographic mechanisms

| Element | Initial design | Rationale |
| --- | --- | --- |
| Authenticated encryption | AES-256-GCM | Protects content confidentiality and detects tampering in one operation. |
| Password-based key derivation | Argon2id | Makes offline password guessing more costly; a strong password is still essential. |
| KDF salt | Fresh random 16-byte salt per encryption | Avoids identical password-derived keys across independent files with overwhelming probability. |
| AES-GCM nonce | Fresh random 12-byte nonce per encryption | Must not repeat with the same key; the per-file salt also yields an independent derived key with overwhelming probability. |
| Authentication tag | 16 bytes (128 bits) | Standard full-length GCM tag. |
| Associated authenticated data (AAD) | Entire file header | Detects unauthorized changes to header fields and configuration parameters. |
| Key management (MVP) | AES key derived from password using Argon2id | Simple initial design; DEK/KEK envelope encryption may be introduced later. |

**Important:** Argon2id's memory, iterations, and parallelism settings require benchmarking on the target computers. They must be bounded when read from an untrusted file. Never use a fixed nonce with the same encryption key. Never invent cryptographic primitives.

## 3. Proposed `.sfe` file format (version 1)

This is a **proposed** binary layout, subject to confirmation before implementation. All integers are unsigned and encoded in big-endian order.

| Order | Field | Size | Notes |
| --- | --- | --- | --- |
| 1 | Magic identifier (`SFE1`) | 4 bytes | Recognizes the format. |
| 2 | Format version | 1 byte | Initially `0x01`. |
| 3 | Argon2id memory cost | 4 bytes | KiB; validate against a safe configured range. |
| 4 | Argon2id time cost | 4 bytes | Positive value; validate against an upper bound. |
| 5 | Argon2id parallelism | 4 bytes | Positive value; validate against an upper bound. |
| 6 | Salt | 16 bytes | Random salt for key derivation. |
| 7 | Nonce | 12 bytes | Random 96-bit GCM nonce. |
| 8 | Ciphertext length | 8 bytes | Length including the 16-byte authentication tag. |
| 9 | Ciphertext + authentication tag | Variable | Output of the authenticated encryption operation. |

**Header length:** 53 bytes. The entire 53-byte header is supplied as **AAD**. The length field must agree with the actual remaining bytes. The initial version does not store an original filename or file extension; the user selects the output destination when decrypting. The application must reject unexpected versions, invalid values, malformed lengths, and unsupported files *before* allocating excessive memory or executing an expensive KDF.

**MVP file-size policy:** Limit file size to a clearly documented maximum (provisionally 64 MiB) while using the one-shot authenticated encryption API. Larger-file chunking requires a separate authenticated framing design and is a later version, not a trivial switch to streaming.

## 4. Encryption flow

1. User selects an existing source file and a new output path and enters a password.
2. Validate source, destination, size limit, and password policy; never overwrite an existing destination by default.
3. Generate fresh random salt and nonce.
4. Derive a 32-byte AES key with Argon2id using the salt and validated parameters.
5. Construct the versioned header with the correct encrypted payload length.
6. Encrypt source bytes with AES-256-GCM using the header as AAD.
7. Write to a temporary file in the destination directory; flush, close, and publish it only on successful completion.
8. If any step fails, remove the temporary result and retain the original.

## 5. Decryption flow

1. User selects a `.sfe` file, a new output path, and enters a password.
2. Parse the fixed-length header. Validate magic, version, bounds, length, and file size before running Argon2id.
3. Derive the AES key using the stored salt and validated KDF parameters.
4. Use the stored nonce, exact header bytes as AAD, and encrypted payload to perform AES-GCM authenticated decryption.
5. If authentication fails, return a generic error and **do not create a plaintext output**.
6. After successful authentication, write the plaintext to a temporary file in the destination directory, then safely publish it without overwriting an existing file.

## 6. Threats, assumptions and residual risks

| Threat | Primary mitigation | Residual risk |
| --- | --- | --- |
| Unauthorized reading of encrypted content | AES-256-GCM | Weak passwords, endpoint compromise, exposed keys. |
| Tampering with encrypted content or header | GCM authentication tag and header as AAD | Does not establish file freshness or prevent deletion. |
| Offline password guessing | Argon2id, strong password guidance | Password guesses remain possible; parameters must be calibrated. |
| Malicious oversized or malformed files | Strict parser, parameter bounds, size limits | Resource exhaustion may still be possible if limits are poor. |
| Accidental overwrite/data loss | Distinct output paths and atomic publish where supported | Device failures or filesystem behavior may limit guarantees. |
| Replay or rollback | Explicitly out of scope for MVP | Old but valid ciphertext may pass authentication. |
| Metadata leakage | Minimal stored header | File size and timing/access patterns remain potentially observable. |

**Trust assumptions:** The operating system, cryptographic library, application process, and password-entry path are not already compromised.

## 7. Acceptance criteria for this design

- [ ] Correct password restores exactly the original bytes, including empty and binary inputs.
- [ ] Incorrect password, modified ciphertext, modified tag, modified authenticated header, or truncated payload never produce an output plaintext file.
- [ ] Fresh files use newly generated salts and nonces.
- [ ] Malformed headers and abusive Argon2id parameters are rejected before expensive processing.
- [ ] Source files are unchanged; destination conflicts are handled without automatic overwrite.
- [ ] No keys or passwords are written to logs, source control, or persistent files.
- [ ] Version 1 file format and limits are documented and covered by automated tests.

## 8. References

- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: GCM and GMAC*: https://doi.org/10.6028/NIST.SP.800-38D
- OWASP, *Key Management Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- OWASP, *Password Storage Cheat Sheet* (Argon2id context): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Python `cryptography`, AESGCM: https://cryptography.io/en/latest/hazmat/primitives/aead/

## 9. Related diagrams

- `diagrams/encryption-activity.puml`
- `diagrams/decryption-activity.puml`
