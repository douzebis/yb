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
yb format     # Initialize PIV objects and optionally generate key pair
yb store      # Store a named blob in the YubiKey
yb fetch      # Retrieve a blob by name
yb ls         # List stored blobs and metadata
yb rm         # Delete a blob by name
yb fsck       # Inspect and verify object integrity
yb self-test  # Run comprehensive end-to-end tests (destructive)
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

## Security: Default Credential Detection

For security, yb automatically checks if your YubiKey uses default credentials and refuses to operate if detected:

- **Default PIN**: 123456
- **Default PUK**: 12345678
- **Default Management Key**: 010203040506070801020304050607080102030405060708

If your YubiKey uses any default credentials, yb will display an error like:

```
Error: YubiKey is using default credentials (INSECURE):
  - PIN (default: 123456, 3 attempts remaining)
  - Management Key (default: 010203...)

This is a security risk. Please change your YubiKey credentials:
  - Change PIN: ykman piv access change-pin
  - Change PUK: ykman piv access change-puk
  - Change Management Key (recommended with PIN-protected mode):
    ykman piv access change-management-key --generate --protect

To proceed anyway (NOT RECOMMENDED), use --allow-defaults flag.
```

**Changing Your Credentials:**

```shell
# Change PIN
ykman piv access change-pin

# Change PUK
ykman piv access change-puk

# Change Management Key (recommended with PIN-protected mode)
ykman piv access change-management-key --generate --protect
```

**Note**: This check requires YubiKey firmware 5.3 or later. On older firmware, yb will display a warning but continue.

**For Testing/Development:**
- Use `--allow-defaults` flag to bypass the check (insecure)
- Set `YB_SKIP_DEFAULT_CHECK=1` environment variable to skip the check entirely

---

## PIN-Protected Management Key Mode

For enhanced security and convenience, yb supports **PIN-protected management key mode**. This allows YubiKeys to store the management key on-device, encrypted and protected by your PIN.

**Why use PIN-protected mode?**
- ✓ More secure than default management key
- ✓ More convenient - no need to provide 48-char hex key
- ✓ You only need to remember your PIN
- ✓ Management key never leaves the YubiKey

**One-time setup:**
```shell
ykman piv access change-management-key --generate --protect
```

**Usage:**
yb automatically detects PIN-protected mode - no `--key` flag needed:
```shell
yb store myfile           # Prompts for PIN if needed
yb --pin 123456 store     # Non-interactive
```

See the [User Guide](USER_GUIDE.md) for more details.

---

## License

MIT License. See `LICENSE` for full text.
