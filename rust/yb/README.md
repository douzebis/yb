<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb

**Secrets on your YubiKey, by name: `yb store`, `yb fetch`.**

[![crates.io](https://img.shields.io/crates/v/yb.svg)](https://crates.io/crates/yb)
[![license](https://img.shields.io/crates/l/yb.svg)](https://github.com/douzebis/yb/blob/main/LICENSES/MIT.txt)

yb keeps small files (API tokens, SSH or GPG keys, a password database)
on a YubiKey 5, in its PIV data objects: about 50 KB in all.  Each blob
is encrypted with a key that never leaves the YubiKey, or derived by it,
and signed or sealed by it, so that tampering is detected before use.  No copy needs to stay on the
computer: the secret travels with the YubiKey.

## Example

```console
$ yb format                      # once: guided, asks before writing anything
$ echo "s3cr3t" | yb store -n api-token
Stored 'api-token' (7 bytes, encrypted)
$ yb store notes.txt
Stored 'notes.txt' (7 bytes, encrypted)
$ yb ls -l                       # no PIN needed: signatures checked with the certificate
-  1  Oct 18 19:20       7  api-token
-  1  Oct 18 19:20       7  notes.txt
$ yb fetch -p api-token
s3cr3t
$ yb rm notes.txt
Removed 'notes.txt'
```

The PIN is asked only when needed (writing, decrypting), at a prompt, or
from `YB_PIN` or `--pin-stdin` for scripts.

## Features

- **Two kinds of store:**
  - **legacy** (`yb format`): P-256 ECDH and AES-256-GCM, ECDSA
    signatures, the PIV PIN;
  - **post-quantum** (`yb format --post-quantum`): keys derived by the
    YubiKey's FIDO2 application (`hmac-secret`), the FIDO2 PIN and one
    touch per blob.
- **Safe writes:** a YubiKey pulled out mid-write keeps the previous
  version; several programs using one YubiKey at once get the outcome of
  running one at a time.
- **A health report:** `yb fsck` shows the YubiKey's PINs, management
  key and store, checks every blob, and with `--nvm` estimates the free
  memory.
- **Several YubiKeys:** `--serial`, or `yb select` to pick one.
- **Scripts:** exit status 2 when a blob is not found, 3 when the store
  is full; `--pin-stdin` reads the PIN, then the payload, from standard
  input.
- **Shell completions** for bash, zsh and fish, blob names included, and
  man pages.

Each guarantee is documented and checked by regression tests against
emulated YubiKeys: [the invariants](https://github.com/douzebis/yb/tree/main/docs/invariants).

## Install

```sh
cargo install --locked yb
```

It builds yb from source, and needs `pkg-config` and two development
libraries:

| | PC/SC | libfido2 |
|---|---|---|
| Debian, Ubuntu | `libpcsclite-dev` | `libfido2-dev` |
| Fedora | `pcsc-lite-devel` | `libfido2-devel` |
| Arch | `pcsclite` | `libfido2` |
| macOS (Homebrew) | built in | `libfido2` |

On Linux, PC/SC's daemon (`pcscd`) must be running.  Also packaged in
nixpkgs (`yb`); on Windows, a preview for legacy stores, on the
[release page](https://github.com/douzebis/yb/releases).

## Which crate?

- **yb:** this command.
- **[`yb-core`](https://crates.io/crates/yb-core):** the same store, as a
  Rust library.
- **[`yubiblob`](https://crates.io/crates/yubiblob):** libyubiblob, the
  same store for C and C++ programs (used by
  [KeePassYB](https://github.com/douzebis/keepassyb), a KeePassXC with
  its database on a YubiKey).

More: [the full documentation](https://github.com/douzebis/yb#readme)
(the cryptography, the storage model, completions, man pages),
[the changelog](https://github.com/douzebis/yb/blob/main/CHANGELOG.md).

## License

MIT.
