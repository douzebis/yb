<!--
SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/douzebis/yb)
[![Crates.io](https://img.shields.io/crates/v/yb.svg)](https://crates.io/crates/yb)

# yb — Secure Blob Storage in Your YubiKey

**yb** is a command-line tool for securely storing, retrieving, and managing
binary blobs directly within a [YubiKey](https://www.yubico.com/products/)
using its PIV application. Blobs are stored under human-friendly names,
optionally encrypted with hardware-backed hybrid cryptography.

**GitHub**: https://github.com/douzebis/yb

---

## Features

- **Store** binary blobs under human-friendly names (files or stdin)
- **Encrypt** data using hybrid ECDH + HKDF-SHA256 + AES-256-GCM, with the
  private key never leaving the YubiKey
- **List**, **fetch**, and **remove** blobs by exact name or glob pattern
- **Multiple YubiKeys** supported via `--serial`
- **PIN-protected management key** mode for convenience and security
- **Shell completions** for bash, zsh, and fish (dynamic blob-name completion)
- **Inspect** low-level store integrity with `fsck`
- No runtime dependencies beyond PC/SC — a single static binary

---

## Installation

### cargo install

```shell
cargo install yb
```

Runtime requirement: a PC/SC daemon must be running (`pcscd` on Linux).
No other external tools are needed.

### Nix (NixOS / nix-shell)

Build and install from the repo:

```shell
nix-build
result/bin/yb --help
```

Or enter a development shell with `yb` on `PATH` and shell completions
activated automatically:

```shell
nix-shell
```

### Build from source

```shell
git clone https://github.com/douzebis/yb
cd yb/rust
cargo build --release
# Binary is at target/release/yb
```

---

## Shell Completions

yb supports dynamic shell completions — blob names and serial numbers are
completed live against the connected YubiKey.

### bash

```shell
source <(YB_COMPLETE=bash yb | sed 's/yb//2;s/yb//2')
```

Add to `~/.bashrc` for persistence.

### zsh

```shell
YB_COMPLETE=zsh yb > ~/.zfunc/_yb
# Ensure ~/.zfunc is in your fpath, then:
autoload -Uz compinit && compinit
```

### fish

```shell
YB_COMPLETE=fish yb > ~/.config/fish/completions/yb.fish
```

When installed via `nix-build`, completion scripts are installed automatically
into the system completion directories.  When using `nix-shell`, bash
completions are activated for the current session automatically.

---

## Quick Start

### 1. Provision the YubiKey store

```shell
# Generate a new ECDH key pair and initialise the blob store
yb format --generate
```

This writes 20 PIV objects (40 KB) to the YubiKey and generates a P-256
key in slot `0x82`.  Run once per YubiKey.

### 2. Store a blob

```shell
# Store a file (blob name defaults to the file's basename)
yb store secret.txt

# Store a file under a specific name
yb store --name my-key secret.txt

# Read from stdin
echo "s3cr3t" | yb store --name api-token

# Store unencrypted
yb store --unencrypted public-cert.pem
```

### 3. Fetch a blob

```shell
# Save to a file in the current directory (filename = blob name)
yb fetch my-key

# Write to stdout
yb fetch --stdout api-token

# Write to a specific file
yb fetch --output recovered.txt my-key

# Fetch multiple blobs matching a glob
yb fetch 'ssh-*'
```

### 4. List blobs

```shell
# Names only
yb list

# Long format (encrypted flag, chunk count, date, size, name)
yb list --long

# Filter by glob
yb list 'ssh-*'

# Sort by date, newest first
yb list --long --sort-time
```

### 5. Remove blobs

```shell
yb remove my-key

# Glob pattern
yb remove 'tmp-*'

# Ignore if not found
yb remove --ignore-missing old-token
```

---

## Command Reference

```
yb [OPTIONS] <COMMAND>

Options:
  -s, --serial <SERIAL>   YubiKey serial number (required with multiple keys)
  -r, --reader <READER>   PC/SC reader name (legacy; prefer --serial)
  -q, --quiet             Suppress informational output
      --pin-stdin         Read PIN from stdin (one line, for scripting)
      --allow-defaults    Allow insecure default credentials (not recommended)
      --debug             Enable debug output
```

| Command | Alias | Description |
|---|---|---|
| `format` | — | Provision PIV objects; optionally generate ECDH key |
| `store` | — | Store a blob (file or stdin) |
| `fetch` | — | Retrieve blob(s) by name or glob |
| `list` | `ls` | List blobs with optional glob filter |
| `remove` | `rm` | Remove blob(s) by name or glob |
| `fsck` | — | Check store integrity and print summary |
| `list-readers` | — | List available PC/SC readers |

Use `yb <command> --help` for full option details.

---

## PIN Handling

yb resolves the PIN in this order:

1. `--pin-stdin` — reads one line from stdin (for scripting and pipelines)
2. `YB_PIN` environment variable
3. Interactive TTY prompt — deferred until a PIN is actually needed

Commands that never need a PIN (`list`, `fsck`) never prompt.

---

## Cryptographic Model

yb uses a **hybrid encryption scheme**:

1. A fresh ephemeral P-256 key pair is generated for each `store` operation.
2. ECDH between the ephemeral key and the YubiKey's resident P-256 key
   produces a shared secret — the YubiKey performs this operation on-card
   via GENERAL AUTHENTICATE; the private key never leaves the device.
3. The shared secret is fed into **HKDF-SHA256** to derive an AES-256 key.
4. The blob is encrypted with **AES-256-GCM** (authenticated encryption).
5. The ephemeral public key, nonce, and ciphertext are stored in the YubiKey
   PIV objects.

Decryption (`fetch`) reverses steps 2–4, again using the YubiKey for ECDH.

Legacy blobs produced by the Python predecessor (AES-256-CBC) are still
readable.

---

## Storage Model

yb stores blobs in custom PIV data objects (retired key certificate slots
`0x5F_0000`–`0x5F_0013`).  Large blobs are split across multiple objects
using a linked-chunk format.  Default store configuration:

| Parameter | Default | Notes |
|---|---|---|
| Object count | 20 | Tunable at format time (`--object-count`) |
| Object size | 2,048 bytes | Tunable at format time (`--object-size`, max 3,052) |
| Gross capacity | ~40 KB | Fits within YubiKey 5's 51,200-byte NVM pool |
| ECDH key slot | `0x82` | Tunable at format time (`--key-slot`) |

---

## Multiple YubiKeys

```shell
# List connected readers
yb list-readers

# Use a specific YubiKey by serial number
yb --serial 12345678 list
yb --serial 12345678 store secret.txt
```

When multiple YubiKeys are connected and `--serial` is omitted, yb prints
the available serials and exits.

---

## Security: Default Credential Detection

yb checks for factory-default credentials (PIN `123456`, PUK `12345678`,
management key `010203...`) and refuses to operate if any are detected.
Change them with:

```shell
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

The last command enables **PIN-protected management key mode**: the
management key is stored on the YubiKey itself, encrypted by your PIN.
yb detects this automatically — no `--key` flag is needed for write
operations.

To bypass the check (testing only): `--allow-defaults` or
`YB_SKIP_DEFAULT_CHECK=1`.

Requires YubiKey firmware 5.3 or later for credential detection.

---

## Format Specification

The yblob binary format is fully documented in
[`doc/YBLOB_FORMAT.md`](doc/YBLOB_FORMAT.md).  It is designed to be
implementation-independent: any tool that can read and write YubiKey PIV data
objects can interoperate with a yblob store without using `yb` itself.

---

## File Format Recognition

The yblob binary format is registered in the
[`file` magic database](https://github.com/file/file) (merged June 2025,
[bug #666](https://bugs.astron.com/view.php?id=666)).  On any system with an
up-to-date `file` installation, raw PIV object dumps are identified
automatically:

```shell
$ file yubikey_object_dump.bin
yubikey_object_dump.bin: yblob object store image data
```

The magic number is `0xF2ED5F0B` (little-endian u32 at offset 0), present in
every PIV object written by yb.

---

## License

MIT License. See `LICENSE` for full text.
