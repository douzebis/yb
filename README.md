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

```shell
# Option 1: Enter a dev environment with dependencies installed via nix-shell
nix-shell

# Option 2: Use nix develop (installs into a .venv for editing)
nix-shell shell-editable.nix

# Option 3: Build the yb derivation (does not activate environment)
nix-build
```

### Installation (Traditional Python)

```shell
# Create and activate a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install --editable .
```

---

## Command Overview

```shell
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

```shell
# Format the store (initialize objects and key)
yb format --generate

# Store a file as a secure blob
yb store --input my-secret.txt my-blob

# Fetch it back
yb fetch --output recovered.txt my-blob
# Please enter User PIN:

# List blobs
yb ls

# Delete a blob
yb rm my-blob
```

---

## Working with Multiple YubiKeys

If you have multiple YubiKeys, use the `--serial` option to select which one to use:

```shell
# Select YubiKey by serial number (printed on device case)
yb --serial 12345678 ls

# Store a blob on a specific YubiKey
yb --serial 12345678 store --input data.txt my-blob
```

**Finding Your Serial Number:**
- Look at your YubiKey case - the serial number is printed on it
- Or let yb tell you when multiple devices are connected

When multiple YubiKeys are connected and you don't specify `--serial`, yb will show you the available serial numbers:

```
Error: Multiple YubiKeys are connected:
  - Serial 12345678 (YubiKey 5.7.1)
  - Serial 87654321 (YubiKey 5.4.3)

Use --serial to select one, for example:
  yb --serial 12345678 <command>
```

**Legacy Option:** The `--reader` option is still supported for PC/SC reader names, but `--serial` is recommended.

---

## License

MIT License. See `LICENSE` for full text.
