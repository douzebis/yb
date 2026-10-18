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

Since 0.2.0 it also reads and writes post-quantum stores (`yb format
--post-quantum`), protected by the YubiKey's FIDO2 application instead:
`yubiblob_store_info()` tells the store's kind, hence which PIN to ask for
(FIDO2 or PIV), and `yubiblob_set_touch_callback()` tells when the YubiKey
waits for a touch (one per blob).

Since 0.3.0, `yubiblob_fetch_unencrypted()` reads an unencrypted blob
without any PIN or touch, for a YubiKey whose PIN is blocked or whose
FIDO2 application was reset: legacy stores check its signature as usual;
post-quantum stores check its checksum only, which detects corruption
but not forgery.

Since 0.4.0, programs may use one YubiKey at once: every read and write
holds the card lock (PC/SC's transaction), so concurrent operations are
serializable (spec 0048).  A session opened with `YUBIBLOB_OPEN_SNAPSHOT`
reads the store once and answers questions from that snapshot until
`yubiblob_refresh()` or a write; `YUBIBLOB_STORE_IF_UNCHANGED` (and
`YUBIBLOB_REMOVE_IF_UNCHANGED`) refuse to overwrite a blob changed on the
YubiKey since (`YUBIBLOB_ERR_CHANGED`, spec 0049).  `yubiblob_remove()`
takes a `flags` argument: the interface version is now 1.

Since 0.5.0, `yubiblob_set_touched_callback()` tells when the YubiKey no
longer waits for a touch (touched, refused or timed out), so that a "Touch
your YubiKey" notice can come down at once.

## Building

With [cargo-c](https://github.com/lu-zero/cargo-c):

```shell
cargo cinstall -p yubiblob --release --prefix /usr/local
pkg-config --cflags --libs yubiblob
```

This installs `libyubiblob` (shared and static), `yubiblob.h` and
`yubiblob.pc`.  It builds on Linux, macOS and Windows (PC/SC comes from
the system: pcsc-lite, PCSC.framework, WinSCard).  On Linux and macOS it
also needs libfido2 (Debian/Ubuntu `libfido2-dev`, Fedora
`libfido2-devel`, Homebrew `libfido2`); on Windows, post-quantum stores
are not supported yet.

For Windows, each yb release carries a prebuilt
`libyubiblob-A.B.C-windows-x86_64.zip` (x86-64, MSVC: `bin/yubiblob.dll`,
`lib/yubiblob.dll.lib`, the static `lib/yubiblob.lib`,
`include/yubiblob.h`), on the
[release page](https://github.com/douzebis/yb/releases).  It is a
preview: built and tested by CI against a simulated YubiKey, not yet on a
real one.

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
