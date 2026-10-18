<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb-core

**Named blobs on a YubiKey, encrypted and signed by it, from Rust.**

[![crates.io](https://img.shields.io/crates/v/yb-core.svg)](https://crates.io/crates/yb-core)
[![docs.rs](https://img.shields.io/docsrs/yb-core)](https://docs.rs/yb-core)
[![license](https://img.shields.io/crates/l/yb-core.svg)](https://github.com/douzebis/yb/blob/main/LICENSES/MIT.txt)

yb-core keeps small files (secrets, keys, a password database) in a
YubiKey 5's PIV data objects: about 50 KB in all, under names you
choose.  Each blob can be encrypted with a key that never leaves the
YubiKey, or derived by it, and is signed or sealed by it, so that
tampering is detected before use.
It is the library under the [`yb`](https://crates.io/crates/yb) command
and libyubiblob, its C interface.

## Guarantees

Each one is documented, and checked by regression tests against emulated
YubiKeys ([the invariants](https://github.com/douzebis/yb/tree/main/docs/invariants)):

| | |
|---|---|
| **Interrupted writes lose nothing** | A YubiKey pulled out, or its memory full, mid-write: the previous version stays. |
| **Several programs, one YubiKey** | Operations take the card's lock, and their outcome is that of running them one at a time. |
| **Tampering is detected before use** | A blob altered on the YubiKey is refused before it is decrypted or returned. |
| **Reading never writes** | Listing and fetching change nothing on the YubiKey. |
| **The management key is never lost** | Changing it is interruption-safe, and it is held in memory that is wiped after use. |

## Features

- **Two kinds of store:**
  - **legacy:** P-256 ECDH and AES-256-GCM, with ECDSA signatures;
  - **post-quantum:** symmetric keys derived by the YubiKey's FIDO2
    application (`hmac-secret`), one touch per blob.
- **Blobs** of any content, compressed when it helps (brotli or xz),
  listed with their sizes and modification times.
- **PINs only when needed:** listing needs none; writing and decrypting
  need the PIN.
- **Snapshots and conditional writes:** read the store once, and write
  only if a blob is still as you last saw it.
- **Testing without a YubiKey:** `VirtualPiv`, a simulated YubiKey in
  memory (feature `virtual-piv`).

## Example

The YubiKey must first be set up with `yb format --post-quantum` (from
the [`yb`](https://crates.io/crates/yb) command), with its FIDO2 PIN
set.

```rust,no_run
use yb_core::{orchestrator, store::Store, Compression, Context, ContextOptions, OutputOptions};

fn main() -> anyhow::Result<()> {
    let mut ctx = Context::new(
        ContextOptions::default(),
        Box::new(|| Ok(None)),     // no PIV PIN: not used by a post-quantum store
        Box::new(|_, _| Ok(None)), // the only YubiKey connected
        OutputOptions::default(),
    )?;
    ctx.fido2_pin_fn = Box::new(|| Ok(std::env::var("YB_PIN").ok()));
    ctx.on_touch = Box::new(|| eprintln!("Touch your YubiKey…"));

    let mut store = Store::from_device(&ctx.reader, ctx.piv.as_ref())?;
    let descriptor = store.descriptor().cloned().expect("a post-quantum store");
    let session = ctx.post_quantum_session()?; // asks for the FIDO2 PIN, once
    let protection = session.protection(&ctx, &descriptor);

    // Store a blob, encrypted and sealed: one touch.
    let stored = orchestrator::store_blob_with(
        &mut store,
        ctx.piv.as_ref(),
        &protection,
        "greeting",
        b"Hello, YubiKey!",
        true, // encrypted
        Compression::Auto,
        None, // the management key: the protection unwraps the store's copy
    )?;
    assert!(stored, "the store is full");

    // List: no PIN, no touch.
    for blob in orchestrator::list_blobs(&store) {
        println!("{}: {} bytes", blob.name, blob.plain_size);
    }

    // Fetch: its seal checked, then decrypted: one touch.
    let data = orchestrator::fetch_blob_with(&store, &protection, "greeting")?;
    assert_eq!(data.as_deref(), Some(&b"Hello, YubiKey!"[..]));
    Ok(())
}
```

Legacy stores (`yb format`, no touch), removal, snapshots and the other
operations: see [the documentation](https://docs.rs/yb-core).

## Building

yb-core links two system libraries, found with `pkg-config`:

| | PC/SC | libfido2 |
|---|---|---|
| Debian, Ubuntu | `libpcsclite-dev` | `libfido2-dev` |
| Fedora | `pcsc-lite-devel` | `libfido2-devel` |
| Arch | `pcsclite` | `libfido2` |
| macOS (Homebrew) | built in | `libfido2` |
| NixOS | `pcsclite` | `libfido2` |

At run time, PC/SC's daemon (`pcscd`) must be running on Linux.  On
Windows, only legacy stores are supported, without libfido2.

## Which crate?

- **[`yb`](https://crates.io/crates/yb):** the command (`yb store`,
  `yb fetch`, `yb ls`…), to set up a YubiKey and manage its blobs.
- **yb-core:** this library, for Rust programs.
- **[`yubiblob`](https://crates.io/crates/yubiblob):** libyubiblob, the
  same store for C and C++ programs (used by
  [KeePassYB](https://github.com/douzebis/keepassyb), a KeePassXC with
  its database on a YubiKey).

More: [the storage format](https://github.com/douzebis/yb/blob/main/docs/YBLOB_FORMAT.md),
[the changelog](https://github.com/douzebis/yb/blob/main/CHANGELOG.md).

## License

MIT.
