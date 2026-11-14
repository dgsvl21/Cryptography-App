# SecureFile — Software Requirements Specification

> **Project:** Cryptography — Assignment 2  
> **Version:** 0.1 (draft for review)  
> **Status:** Planning; no features have been implemented yet  
> **Language:** English

## 1. Purpose

Develop a **local desktop application** named *SecureFile* that encrypts and decrypts files using established cryptographic mechanisms, providing confidentiality and detection of unauthorized modifications to encrypted data.

The project is part of the practical assignment for the Cryptography course. This specification also serves as public documentation for the GitHub repository.

## 2. Scope and Assumptions

- **Initial platform:** Windows; Python is the planned implementation language.
- **Primary user:** Someone who wants to protect local files with a password.
- **Candidate technologies:** AES-256-GCM for authenticated encryption; Argon2id for key derivation; PySide6 for the graphical user interface. Final choices will be justified during cryptographic design.
- The initial version requires **no server or database**.
- Users are responsible for safeguarding their passwords. Losing a password may make encrypted files unrecoverable.
- The application does not guarantee secure deletion of pre-existing plaintext copies or protection against a compromised operating system.

### 2.1 Out of Scope for the MVP

Cloud storage, user accounts, synchronization, remote file sharing, centralized password recovery, full-disk encryption, and advanced key-recovery or revocation features. These may be explored in a later version.

## 3. Conventions

- **FR:** Functional Requirement; **NFR:** Non-Functional Requirement.
- **M:** Must-have for the MVP; **D:** Desirable; **F:** Future.
- **Acceptance criterion:** Observable, testable behavior used to verify a requirement.
- All requirements have a **Planned** status until implementation and supporting test evidence exist.

## 4. Functional Requirements

| ID | Priority | Requirement | Summary acceptance criterion |
|---|---|---|---|
| FR-01 | M | Allow users to select a local input file. | The application validates that the source exists and is readable. |
| FR-02 | M | Allow users to select encryption or decryption. | The selected operation produces the corresponding result. |
| FR-03 | M | Request a password without displaying it in plaintext by default. | The interface masks the password by default. |
| FR-04 | M | Derive key material from the password using a suitable KDF, a salt, and parameters stored in the encrypted file format. | The same password and parameters derive the required key; an incorrect password fails authentication. |
| FR-05 | M | Encrypt content using AES-256-GCM with an appropriate IV/nonce. | The output does not contain plaintext file content; a nonce is never reused with the same key. |
| FR-06 | M | Save encrypted output in a custom, versioned file format containing the metadata needed for decryption. | The relevant application version can parse the resulting file. |
| FR-07 | M | Decrypt valid files using the correct password. | Recovered bytes exactly match the original file. |
| FR-08 | M | Verify authenticity/integrity before releasing decrypted data. | Modified files, invalid tags, or tampered authenticated parameters are rejected. |
| FR-09 | M | Handle incorrect passwords and invalid files without producing decrypted output. | The operation fails safely and does not publish partial output. |
| FR-10 | M | Preserve the source file and prevent unintended destination overwrites. | The source remains unchanged after success or failure; destination conflicts are handled explicitly. |
| FR-11 | M | Support binary files and empty files. | Tests with text, images, and empty files recover the exact original bytes. |
| FR-12 | M | Display completion confirmations or understandable error messages without exposing secrets. | Messages do not contain passwords, keys, or sensitive file content. |
| FR-13 | D | Show progress and keep the interface responsive during long operations. | The window remains responsive during supported processing. |
| FR-14 | D | Support large files through authenticated chunk processing with order and completeness checks. | Files above a defined threshold are processed without loading their entire contents into RAM. |
| FR-15 | F | Support protected sharing through an asymmetric mechanism with authenticated public keys. | Only the authorized recipient can recover the key material. |
| FR-16 | F | Separate data encryption keys (DEKs) and key encryption keys (KEKs) to allow key-protection rotation. | Where applicable, a KEK can be replaced without re-encrypting file contents. |

## 5. Non-Functional Requirements

| ID | Category | Priority | Requirement / verification condition |
|---|---|---|---|
| NFR-01 | Security | M | Use reputable, maintained cryptographic libraries; do not implement AES or Argon2 from scratch. |
| NFR-02 | Security | M | Generate or derive keys using suitable mechanisms; never store plaintext passwords or keys in encrypted files or logs. |
| NFR-03 | Security | M | Ensure nonce uniqueness per key and document KDF parameters; reject malformed or unreasonably large headers. |
| NFR-04 | Integrity | M | Authentication failures must not release plaintext or create final output files that appear valid. |
| NFR-05 | Reliability | M | Do not modify source files; use temporary output and publish the destination only on success; handle interruptions and I/O failures. |
| NFR-06 | Compatibility | M | Run on Windows with an explicitly documented Python version. |
| NFR-07 | Usability | M | Make primary operations understandable, confirm source and destination, and provide clear error messages. |
| NFR-08 | Testability | M | Provide automated tests for encryption, decryption, tampering, and edge cases. |
| NFR-09 | Maintainability | M | Separate the interface, file services, file format, and cryptographic engine; document dependencies and design decisions. |
| NFR-10 | Privacy | M | Do not transmit files, passwords, or keys to external services in the initial version. |
| NFR-11 | Performance | D | Define and measure processing times and memory usage using representative file sizes; avoid unmeasured performance claims. |
| NFR-12 | Extensibility | D | Use a versioned format that allows future changes with explicit validation of supported versions. |
| NFR-13 | Documentation | M | Keep the README, requirements, threat model, cryptographic decisions, and usage instructions up to date on GitHub. |

## 6. Preliminary Rules and Decisions

1. Encryption must not automatically delete or replace original files.
2. Decryption is successful only after authentication has passed.
3. Salts and nonces may be stored alongside ciphertext. They are not secret, but must be generated and managed correctly.
4. Header information that affects interpretation must be authenticated (for example, as AEAD associated data).
5. AES-GCM alone must not be presented as protection against rollback, file deletion, or active malware.
6. The final encrypted file format and size limits will be defined during cryptographic design.

## 7. Overall MVP Acceptance Criteria

The MVP may be considered complete when:

- [ ] A text file can be encrypted and recovered byte for byte.
- [ ] An image or another binary file can be encrypted and recovered byte for byte.
- [ ] An empty file can be encrypted and recovered correctly.
- [ ] An incorrect password is rejected without producing a final plaintext file.
- [ ] Tampering with ciphertext, its tag, or authenticated metadata causes rejection.
- [ ] The application does not modify source files or overwrite destinations without explicit user action.
- [ ] An incomplete or malformed file is rejected safely.
- [ ] Documentation and automated tests make the validation reproducible.

## 8. Preliminary Traceability

| Objective | Related requirements |
|---|---|
| Confidentiality | FR-03 to FR-07; NFR-01 to NFR-03; NFR-10 |
| Integrity and authenticity | FR-05; FR-08; FR-09; NFR-04 |
| Preservation and recovery | FR-07; FR-09 to FR-11; NFR-05 |
| User experience | FR-01 to FR-03; FR-12; FR-13; NFR-07 |
| Project quality | NFR-06; NFR-08; NFR-09; NFR-12; NFR-13 |

## 9. Open Questions for the Next Phases

- Confirm whether a GUI and optional text encryption are required by the course assignment.
- Choose the Python version, Argon2id parameters, and binary `.sfe` file format.
- Define MVP file-size limits and the strategy for processing larger files.
- Detail the use cases and threat model.
- Decide whether secure file sharing will be included as a future enhancement.

## 10. Technical References for Future Decisions

- NIST SP 800-38D — GCM and GMAC: https://doi.org/10.6028/NIST.SP.800-38D
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- PyCA cryptography: https://cryptography.io/en/stable/

---

*This is an initial specification subject to revision during analysis, modeling, and design. Requirements and priorities do not imply that any feature has already been implemented.*
