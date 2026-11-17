# Cryptography App

**A Python desktop application for secure file encryption and decryption.**

Cryptography App is an educational software project focused on applying modern cryptographic principles to protect local files. It combines authenticated encryption, password-based key derivation, and a straightforward desktop interface, with an emphasis on security, modularity, and maintainable code.

The project was conceived as part of a university Cryptography assignment and is also intended to demonstrate practical software engineering skills.

## Overview

The application is designed to let users protect files with a password and recover them when needed. All encryption and decryption operations are intended to run locally, without requiring a user account, cloud service, or external server.

Its design emphasizes three goals:

- **Confidentiality:** prevent unauthorized parties from reading protected file contents.
- **Integrity and authenticity:** detect changes to encrypted data before releasing decrypted content.
- **Usability:** offer a clear workflow for selecting files, entering a password, and managing results.

## Core Capabilities

- **File encryption and decryption** using authenticated encryption.
- **Password-based protection** through cryptographic key derivation.
- **Tamper detection** for encrypted files and authenticated metadata.
- **Local file handling** with input validation and safeguards against accidental overwrites.
- **Desktop graphical interface** for everyday use on Windows.
- **Automated tests** covering the cryptographic components and error scenarios.

## Technology Stack

| Area                     | Technology                   | Purpose                                          |
| ------------------------ | ---------------------------- | ------------------------------------------------ |
| Programming language     | Python                       | Application logic and modular implementation     |
| Authenticated encryption | AES-256-GCM (`cryptography`) | Confidentiality and integrity of protected data  |
| Key derivation           | Argon2id (`argon2-cffi`)     | Derive encryption keys from user passwords       |
| Desktop interface        | PySide6 (Qt for Python)      | Graphical user interface                         |
| Testing                  | pytest                       | Automated verification and regression testing    |
| Version control          | Git & GitHub                 | Source control, collaboration, and documentation |

## How It Works

**Encryption**

1. The user selects a file and provides a password.
2. The application generates a random salt and derives a key using Argon2id.
3. AES-256-GCM encrypts and authenticates the file contents using a unique nonce.
4. The protected output includes the information required for subsequent decryption, such as the salt, nonce, and format metadata.

**Decryption**

1. The user selects a protected file and enters the password.
2. The application reads and validates the encrypted file format.
3. The key is derived again using the stored salt and parameters.
4. AES-GCM verifies authentication before the original content is made available.

_This is a high-level description of the intended application behavior, not a claim that every component is already implemented._

## Architecture

The application follows a modular design that separates user interaction, application workflows, cryptographic operations, and file handling:

```text
cryptography_app/
├── crypto/       # Encryption and key derivation
├── services/     # Application workflows
├── storage/      # File I/O and encrypted-file handling
└── gui/          # Desktop user interface

tests/           # Automated tests
docs/            # Requirements, design notes, and diagrams
```

The goal of this separation is to keep security-sensitive logic independent of the graphical interface and easier to test.

## Security Considerations

Cryptography App is designed around established cryptographic primitives rather than custom encryption algorithms. However, encryption cannot guarantee protection in every scenario:

- **Password strength matters.** Argon2id raises the cost of password guessing but cannot make a weak password unguessable.
- **Local device security matters.** Malware, keyloggers, and compromised operating systems are outside the protection provided by file encryption alone.
- **Encrypted files may expose metadata**, including approximate file size and the existence of protected files.
- **Secure deletion is not guaranteed.** Existing plaintext copies, backups, and temporary data may remain elsewhere on a device.

This project is intended for learning and demonstration. Security-sensitive use should depend on a completed implementation, appropriate testing, and independent review.

## Getting Started

The project targets Windows and Python 3.13 or a compatible version. From the repository root:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the automated tests with:

```powershell
python -m pytest -v
```

The graphical application entry point will be documented when a distributable application is available.

## Documentation

Technical documentation is organized in the [`docs/`](docs/) directory, including software requirements, cryptographic design, threat modeling, and PlantUML diagrams.

## License

See the [LICENSE](LICENSE) file for the repository's license terms.
