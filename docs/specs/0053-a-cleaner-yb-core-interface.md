<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0053 — A Cleaner yb-core Interface

**Status:** draft (an embryo, for a release after 0.7.x)
**App:** yb-core
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb-core's public interface grew with the `yb` command and libyubiblob,
which call it; a Rust program using it directly meets their internals.
Found while writing yb-core's README for 0.7.1 (its example, compiled as
a doctest, had to show all of this):

- **Two shapes for the same operations:**
  - the older functions (`store_blob`, `store_blob_checked`,
    `fetch_blob`, `remove_blobs_checked`) take the public key, the
    management key, the PIN, the reader and a debug flag one by one;
    only legacy stores use them;
  - the newer ones (`store_blob_with`, `store_blob_with_checked`,
    `fetch_blob_with`) take a `&dyn Protection` that carries them.
- **No constructor for a legacy store's protection:**
  `session.protection(&ctx, &descriptor)` builds a post-quantum store's;
  `LegacyProtection` has seven public fields to fill by hand (`piv`,
  `reader`, `slot`, `encryption_key`, `verifying_key`, `pin`, `debug`).
  So the cleaner shape is only usable, in practice, for post-quantum
  stores.
- **Positional arguments that need comments to read:**
  `store_blob_with(store, piv, &protection, name, payload, true,
  Compression::Auto, None)`: `true` is "encrypted", `None` the management
  key.  Five functions carry `#[allow(clippy::too_many_arguments)]`.
- **`Context` set up in two steps:** `Context::new` takes the PIV PIN
  callback and a device picker; the FIDO2 PIN callback and the touch
  callbacks are public fields to assign afterwards (`fido2_pin_fn`,
  `on_touch`, `on_touched`).  Other public fields expose internals
  (`management_key`, `defaults`, `allow_defaults`).
- **The descriptor is cloned before a write:**
  `store.descriptor().cloned()`, because the protection borrows it while
  the write borrows the store mutably.
- **PINs leave zeroizing memory:** `Context::require_pin` returns a plain
  `String`, copied from the `Zeroizing` buffer it caches.
- **The crate documentation's quick start** passes a PIN in
  `ContextOptions::pin`, against the advice of keeping PINs off code
  and command lines (spec 0034).
- **The store's kind decides the calls:** a program must test
  `store.kind` and choose the legacy or the post-quantum path itself.

## Goals

- One way to do each operation, for either kind of store: a program
  writes the same code for a legacy and a post-quantum store.
- Calls that read without comments: no positional `bool` or `None`.
- A context built in one step, with its callbacks.
- Secrets stay in `Zeroizing` buffers across the interface.
- The README's example and the crate's quick start become the same
  short program.

## Non-goals

- **libyubiblob's C interface:** unchanged (its ABI version stays); only
  its Rust implementation follows.
- **The storage format and the guarantees** (invariants): unchanged.
- **The `yb` command's behavior:** unchanged.

## Specification

To be written.  Directions, to be weighed:

- **One protection for either kind of store:** `ctx.protection(&store)`
  (or a `Session` type owning the context, the store and the
  protection), asking for the right PIN (PIV or FIDO2) when first
  needed.
- **A constructor for `LegacyProtection`,** if it stays public.
- **An options struct for writes,** with a builder or named fields:
  `Write { encrypted, compression, before_write }`; the management key
  comes from the protection or the context, never as an argument.
- **`ContextBuilder`:** the reader or serial, the PIN callbacks, the
  touch callbacks, the device picker; `Context`'s fields private, with
  accessors where callers need them.
- **The descriptor owned by the protection** (or reference-counted), so
  that writes need no clone.
- **`require_pin` returning `Zeroizing<String>`.**
- **Deprecate the older functions** for one release, then remove them.
- **Semver:** a breaking change for yb-core (0.x: a minor version);
  yb and yubiblob move with it.

## Invariants

- None created or changed: the invariants concern the store, not the
  interface.  Their regression tests must pass unchanged.

## Open questions

- A `Session` type, or functions on a `Protection`?
- Keep `orchestrator` as the module of operations, or methods on
  `Store`?
- Is a device picker needed in the context, or is selecting a YubiKey
  (by serial or reader) enough for a library?

## References

- yb-core's README (0.7.1): the example that showed these.
- [spec 0028](0028-post-quantum-protection.md): post-quantum stores,
  `PostQuantumProtection`.
- [spec 0034](0034-secrets-hygiene-and-hardening.md): secrets off
  command lines.
- [spec 0049](0049-snapshots.md): `before_write`, snapshots.
