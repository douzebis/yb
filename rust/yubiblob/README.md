<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# libyubiblob

A small, safe blob store on a YubiKey, for C and C++ programs: the C
interface of [yb](https://github.com/douzebis/yb).

libyubiblob keeps named blobs in the YubiKey's PIV application, encrypted
to a key that never leaves the YubiKey and signed by it.  Programs list,
fetch, store and remove blobs in their own process, with typed status
codes and the PIN passed in memory.  It keeps yb's guarantees: an
interrupted write (YubiKey pulled out, card memory exhausted) loses
nothing, reading never writes, and tampering is detected before use.

It assumes a YubiKey set up with `yb format` (management key kept on the
YubiKey, unlocked by the PIN).

## Building

With [cargo-c](https://github.com/lu-zero/cargo-c):

```shell
cargo cinstall -p yubiblob --release --prefix /usr/local
pkg-config --cflags --libs yubiblob
```

This installs `libyubiblob` (shared and static), `yubiblob.h` and
`yubiblob.pc`.  It builds on Linux, macOS and Windows (PC/SC comes from
the system: pcsc-lite, PCSC.framework, WinSCard).

## Using

```c
#include <stdio.h>
#include <yubiblob.h>

/* pin, pin_len: the PIN, as the user typed it (not NUL-terminated). */
yubiblob_session_t* s = NULL;
if (yubiblob_open(0, 0, &s) == YUBIBLOB_OK) {   /* the only YubiKey connected */
    uint8_t* data = NULL;
    size_t len = 0;
    if (yubiblob_fetch(s, "vault.kdbx", pin, pin_len, &data, &len) == YUBIBLOB_OK) {
        /* … use data … */
        yubiblob_buffer_free(data, len);         /* overwritten, then freed */
    } else {
        fprintf(stderr, "%s\n", yubiblob_last_error());
    }
    yubiblob_close(s);
}
```

The interface, its rules (memory, strings, errors, threads) and its
versioning are specified in
[spec 0039](https://github.com/douzebis/yb/blob/main/docs/specs/0039-c-api.md).
Before 1.0, each minor version may change the interface; check
`yubiblob_abi_version()` against `YUBIBLOB_ABI_VERSION` at run time.

## License

MIT.
