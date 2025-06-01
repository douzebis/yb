<!--
SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb — Secure Blob Storage in Your YubiKey

**yb** is a command-line tool for securely storing, retrieving, and managing
small binary blobs directly within a [YubiKey](https://www.yubico.com/products/)
using its PIV application. It enables encrypted, name-based storage with hybrid
cryptography, leveraging the hardware-backed security of your YubiKey.

**GitHub**: https://github.com/douzebis/yb

---

## Features

- **Store** binary blobs under human-friendly names
- **Encrypt** data using hybrid ECDH + AES-256 encryption with a YubiKey-stored key
- **List**, **fetch**, and **delete** blobs by name
- **Inspect** low-level object storage for debugging (`fsck`)
- Designed for use with custom PIV data objects on the YubiKey

---

## Getting Started

### Installation (NixOS)

Choose one of the following:

```bash
# Option 1: Enter a dev environment with dependencies installed via nix-shell
nix-shell

# Option 2: Use nix develop (installs into a .venv for editing)
nix develop -f shell-editable.nix

# Option 3: Build the yb derivation (does not activate environment)
nix-build
```

### Installation (Traditional Python)

```bash
# Create and activate a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install --editable .
```

---

## Command Overview

```bash
yb format   # Initialize PIV objects and optionally generate key pair
yb store    # Store a named blob in the YubiKey
yb fetch    # Retrieve a blob by name
yb ls       # List stored blobs and metadata
yb rm       # Delete a blob by name
yb fsck     # Inspect and verify object integrity
```

Use `--help` with any command for detailed options.

---

## Cryptographic Model

yb uses a **hybrid encryption scheme**:

- An ephemeral EC P-256 key is generated on each `store` or `fetch` call
- A persistent P-256 key in the YubiKey is used for ECDH
- The derived shared secret feeds into **HKDF-SHA256**, producing an AES-256 key
- Blob data is encrypted using **AES-CBC with PKCS7 padding**
- Encrypted chunks are stored in custom PIV objects

---

## Example Usage

```bash
# Format the store (initialize objects and key)
yb format --generate

# Store a file as a secure blob
yb store --in my-secret.txt my-blob

# Fetch it back
yb fetch --out recovered.txt my-blob  # Here you'll be asked for the PIN

# List blobs
yb ls

# Delete a blob
yb rm my-blob
```

---

## License

MIT License. See `LICENSE` for full text.
