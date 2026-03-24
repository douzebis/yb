<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

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
- **Sign** every stored blob with a P-256 ECDSA signature for tamper detection
- **Integrity checking** in both `list` and `fsck` — CORRUPTED blobs are
  flagged automatically, no PIN required
- **List**, **fetch**, and **remove** blobs by exact name or glob pattern
- **Multiple YubiKeys** supported via `--serial`
- **PIN-protected management key** mode for convenience and security
- **Shell completions** for bash, zsh, and fish (dynamic blob-name completion)
- No runtime dependencies beyond PC/SC — a single static binary

---

## Installation

### NixOS / nix-shell

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

### cargo install (Debian, Arch, Fedora, macOS, …)

First, install the PC/SC development library for your distribution:

```shell
# Debian / Ubuntu
sudo apt install pkgconf libpcsclite-dev

# Arch
sudo pacman -S pkgconf pcsclite

# Fedora
sudo dnf install pkgconf pcsc-lite-devel

# macOS — PC/SC is built into the OS; no extra library needed
```

Then:

```shell
cargo install yb
```

Runtime requirement: a PC/SC daemon must be running (`pcscd` on Linux).
No other external tools are needed.

> **Man pages:** `cargo install` does not install man pages.  To generate
> them locally, run:
>
> ```shell
> cargo install --bin yb-gen-man yb
> yb-gen-man /usr/local/share/man/man1
> ```
>
> Or, if you have the source tree available:
>
> ```shell
> cargo run --manifest-path rust/Cargo.toml --bin yb-gen-man -- /usr/local/share/man/man1
> ```

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

```shell
# One-time setup: generate a P-256 key and enable PIN-protected management key
yb format --generate --protect

# Stash a secret
echo "s3cr3t" | yb store -n api-token

# Retrieve it
yb fetch -p api-token

# See what's there — signatures verified automatically, no PIN needed
yb ls -l

# Something feels off? Check the store
yb fsck --nvm
```

For full option details: `yb <command> --help` or `man yb`.

---

## PIN Handling

yb resolves the PIN in this order:

1. `--pin-stdin` — reads one line from stdin (for scripting and pipelines)
2. `YB_PIN` environment variable
3. Interactive TTY prompt — deferred until a PIN is actually needed

Commands that never need a PIN (`list`, `fsck`) never prompt.
Both perform signature verification using only the public key from the
store's X.509 certificate.

> **Security note:** `YB_PIN` and `--pin-stdin` are convenient for
> scripting but carry OS-level exposure risks.  `YB_PIN` is visible to
> child processes and, on some systems, to other users via `/proc`.
> `--pin-stdin` is the safer non-interactive option — pipe the PIN on
> stdin rather than setting an environment variable when possible.
> The default interactive TTY prompt (`rpassword`) has no such exposure.

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
| Object count | 32 | Tunable at format time (`--object-count`) |
| Max object size | 3,063 bytes | Each PIV object is written at the size its content requires |
| Gross capacity | up to ~61 KB | Shared with other PIV data; YubiKey 5 NVM pool is 51,200 bytes |
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
Change the PIN and PUK with:

```shell
ykman piv access change-pin
ykman piv access change-puk
```

For the management key, the recommended approach is **PIN-protected mode**:
the management key is replaced with a random value stored on the YubiKey
itself, protected by your PIN.  yb detects this automatically — no `--key`
flag is needed for write operations.

Enable it in one step at format time:

```shell
yb format --generate --protect
```

Or, if you have already formatted and want to enable it separately:

```shell
ykman piv access change-management-key --generate --protect
```

To bypass the default-credential check (testing only): `--allow-defaults` or
`YB_SKIP_DEFAULT_CHECK=1`.

Requires YubiKey firmware 5.3 or later for credential detection.

---

## Format Specification

The yblob binary format is fully documented in
[`docs/YBLOB_FORMAT.md`](docs/YBLOB_FORMAT.md).  It is designed to be
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
