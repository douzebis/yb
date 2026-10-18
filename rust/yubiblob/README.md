<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# libyubiblob

**Named blobs on a YubiKey, encrypted and signed by it, from C and C++.**

[![crates.io](https://img.shields.io/crates/v/yubiblob.svg)](https://crates.io/crates/yubiblob)
[![license](https://img.shields.io/crates/l/yubiblob.svg)](https://github.com/douzebis/yb/blob/main/LICENSES/MIT.txt)

libyubiblob keeps small files (secrets, keys, a password database) in a
YubiKey 5's PIV data objects: about 50 KB in all, under names you
choose.  Each blob can be encrypted with a key that never leaves the
YubiKey, or derived by it, and is signed or sealed by it, so that
tampering is detected before use.  It is the C interface of
[yb](https://github.com/douzebis/yb): programs list, fetch, store and
remove blobs in their own process, with typed status codes and the PIN
passed in memory.

## Guarantees

Each one is documented, and checked by regression tests against emulated
YubiKeys ([the invariants](https://github.com/douzebis/yb/tree/main/docs/invariants)):

| | |
|---|---|
| **Interrupted writes lose nothing** | A YubiKey pulled out, or its memory full, mid-write: the previous version stays. |
| **Several programs, one YubiKey** | Every read and write holds the card's lock, and their outcome is that of running them one at a time. |
| **Tampering is detected before use** | A blob altered on the YubiKey is refused before it is decrypted or returned. |
| **Reading never writes** | Listing and fetching change nothing on the YubiKey. |

## Features

- **Two kinds of store,** told apart by `yubiblob_store_info()`:
  - **legacy** (`yb format`): P-256 ECDH and AES-256-GCM, ECDSA
    signatures, the PIV PIN;
  - **post-quantum** (`yb format --post-quantum`): keys derived by the
    YubiKey's FIDO2 application (`hmac-secret`), the FIDO2 PIN and one
    touch per blob, announced by `yubiblob_set_touch_callback()` and
    `yubiblob_set_touched_callback()`.
- **PINs only when needed:** listing needs none; writing and decrypting
  need the PIN.  `yubiblob_fetch_unencrypted()` reads an unencrypted blob
  without any PIN or touch, for a YubiKey whose PIN is blocked.
- **Snapshots and conditional writes:** `YUBIBLOB_OPEN_SNAPSHOT` reads
  the store once; `YUBIBLOB_STORE_IF_UNCHANGED` writes only if the blob
  is still as the snapshot saw it (`YUBIBLOB_ERR_CHANGED` otherwise).
- **Secrets wiped:** fetched content is overwritten when freed
  (`yubiblob_buffer_free()`).

## Example

The YubiKey must first be set up with `yb format` (from the
[`yb`](https://crates.io/crates/yb) command).

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yubiblob.h>

static void touch(void* user) { (void)user; fprintf(stderr, "Touch your YubiKey…\n"); }

int main(void) {
    const char* pin = getenv("YB_PIN"); /* the PIV PIN, or the FIDO2 PIN (post-quantum) */
    size_t pin_len = pin ? strlen(pin) : 0;

    yubiblob_session_t* s = NULL;
    if (yubiblob_open(0, 0, &s) != YUBIBLOB_OK) { /* 0: the only YubiKey connected */
        fprintf(stderr, "%s\n", yubiblob_last_error());
        return 1;
    }
    yubiblob_set_touch_callback(s, touch, NULL); /* post-quantum stores: one touch per blob */

    /* Store a blob, encrypted and signed. */
    const char hello[] = "Hello, YubiKey!";
    yubiblob_status_t st = yubiblob_store(s, "greeting", (const uint8_t*)hello, strlen(hello),
                                          YUBIBLOB_STORE_ENCRYPT, (const uint8_t*)pin, pin_len);

    /* List: no PIN needed. */
    yubiblob_blob_info_t* blobs = NULL;
    size_t count = 0;
    if (st == YUBIBLOB_OK && (st = yubiblob_list(s, &blobs, &count)) == YUBIBLOB_OK) {
        for (size_t i = 0; i < count; i++)
            printf("%s: %u bytes\n", blobs[i].name, blobs[i].size);
        yubiblob_blobs_free(blobs, count);
    }

    /* Fetch: checked, then decrypted by the YubiKey. */
    uint8_t* data = NULL;
    size_t len = 0;
    if (st == YUBIBLOB_OK
        && (st = yubiblob_fetch(s, "greeting", (const uint8_t*)pin, pin_len, &data, &len)) == YUBIBLOB_OK) {
        printf("%.*s\n", (int)len, (const char*)data);
        yubiblob_buffer_free(data, len); /* overwritten, then freed */
    }

    if (st != YUBIBLOB_OK)
        fprintf(stderr, "%s\n", yubiblob_last_error());
    yubiblob_close(s);
    return st == YUBIBLOB_OK ? 0 : 1;
}
```

```sh
cc example.c $(pkg-config --cflags --libs yubiblob) -o example
```

The interface, its rules (memory, strings, errors, threads) and its
versioning: [spec 0039](https://github.com/douzebis/yb/blob/main/docs/specs/0039-c-api.md),
and the comments of `yubiblob.h`.  Before 1.0, a minor version may
change the interface: check `yubiblob_abi_version()` against
`YUBIBLOB_ABI_VERSION` at run time.

## Building

With [cargo-c](https://github.com/lu-zero/cargo-c):

```sh
cargo cinstall -p yubiblob --release --prefix /usr/local
```

This installs `libyubiblob` (shared and static), `yubiblob.h` and
`yubiblob.pc`.  It needs `pkg-config`, and two development libraries:

| | PC/SC | libfido2 |
|---|---|---|
| Debian, Ubuntu | `libpcsclite-dev` | `libfido2-dev` |
| Fedora | `pcsc-lite-devel` | `libfido2-devel` |
| Arch | `pcsclite` | `libfido2` |
| macOS (Homebrew) | built in | `libfido2` |

On Linux, PC/SC's daemon (`pcscd`) must be running.  On Windows, a
prebuilt preview for legacy stores
(`libyubiblob-A.B.C-windows-x86_64.zip`: the DLL, its import library, a
static library and the header) is on the
[release page](https://github.com/douzebis/yb/releases).

## Which crate?

- **[`yb`](https://crates.io/crates/yb):** the command, to set up a
  YubiKey and manage its blobs.
- **[`yb-core`](https://crates.io/crates/yb-core):** the same store, as a
  Rust library.
- **yubiblob:** this library, for C and C++ programs.  Used by
  [KeePassYB](https://github.com/douzebis/keepassyb), a KeePassXC with its
  database on a YubiKey.

More: [the storage format](https://github.com/douzebis/yb/blob/main/docs/YBLOB_FORMAT.md),
[the changelog](https://github.com/douzebis/yb/blob/main/CHANGELOG.md).

## License

MIT.
