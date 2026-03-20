# Code Review — yb Rust codebase

Date: 2026-03-20

## 1. Duplicated code

### 1.1 `parse_tlv_flat` / `decode_length` — three copies

The same flat BER-TLV parser exists in three places:

| Location | Name |
|---|---|
| `yb-core/src/auxiliaries.rs` | `parse_tlv` |
| `yb-core/src/piv/hardware.rs` | `parse_tlv_flat` |
| `yb-core/src/piv/virtual_piv.rs` | `parse_tlv_flat` |

`decode_length` is duplicated between `hardware.rs` and `virtual_piv.rs`; `auxiliaries.rs`
inlines the same logic directly.  The three implementations are slightly
different (the `auxiliaries` version uses `i + 1 <` as the loop guard instead
of `i <`; the two `parse_tlv_flat` copies are byte-for-byte identical).

Fix: move `parse_tlv_flat` and `decode_length` into `auxiliaries.rs` (already
`pub`), re-export or `pub(crate)` them, and delete the copies in `hardware.rs`
and `virtual_piv.rs`.

### 1.2 `extract_pin_protected_key` — two copies

Present verbatim in both `hardware.rs` (lines 564–574) and `virtual_piv.rs`
(lines 473–483).  Both parse `88 <len> [ 89 <len> <key> ]` from the PRINTED
object and return `hex::encode(key_bytes)`.

Fix: move to `auxiliaries.rs`, call from both backends.

### 1.3 Management-key resolution pattern — duplicated in two backends

`write_object` and `generate_certificate` in `hardware.rs` both contain:

```rust
let key_hex: String;
let effective_key: &str = if let Some(k) = management_key {
    k
} else if let Some(p) = pin {
    session.verify_pin(p)?;
    let raw = session.get_data(OBJ_PRINTED)?;
    key_hex = extract_pin_protected_key(&raw)?;
    &key_hex
} else {
    bail!("...: management_key or pin required");
};
```

`virtual_piv.rs` has `authenticate_for_write` which does the same thing.
`hardware.rs` can't share the identical helper because it needs a live
`PcscSession` for the same-session constraint — but the pattern could be
extracted into a method on `PcscSession`.

### 1.4 PIN-derived deprecation bail — duplicated in `Context::new` and `Context::with_backend`

The block:

```rust
if pin_derived {
    bail!("PIN-derived management key mode is deprecated ...");
}
```

appears identically in both constructors.  Extract into a free function
`reject_pin_derived(pin_derived: bool) -> Result<()>`.

### 1.5 `subject` DN parsing — duplicated in `hardware.rs` and `virtual_piv.rs`

Both `generate_certificate` implementations parse `"CN=foo/O=bar"` with:

```rust
for part in subject.split('/').filter(|s| !s.is_empty()) {
    if let Some((key, val)) = part.split_once('=') {
        match key.trim() {
            "CN" => dn.push(DnType::CommonName, val.trim()),
            ...
        }
    }
}
```

Fix: extract into a free function `parse_subject_dn(subject: &str) -> DistinguishedName`.

### 1.6 `general_authenticate_ecdh` and `general_authenticate_sign` share boilerplate

Both build `7C <len> [ 82 00  <payload_tag> <len> <data> ]`, send `00 87 11
<slot>`, and parse `7C → 82` from the response.  The only differences are the
inner tag (0x85 vs 0x81) and the label string.  A private helper method
`general_authenticate(slot, inner_tag, payload, label)` would eliminate the
repetition.

---

## 2. Non-idiomatic constructs

### 2.1 `if pk.is_none().into() { bail!(...) } Ok(pk.unwrap())` in `context.rs`

`CtOption::is_none()` returns a `subtle::Choice`, which is why `.into()` is
needed to coerce it to `bool`.  The idiomatic form with `subtle` is:

```rust
let pk: Option<_> = pk.into();
pk.ok_or_else(|| anyhow::anyhow!("EC point not on P-256 curve"))
```

Or just use `.unwrap_or_else` since the `bail!` right after is the only path.

### 2.2 Mutable binding introduced only to pass as `&str` in `write_object` / `generate_certificate`

```rust
let key_hex: String;
let effective_key: &str = if let Some(k) = management_key { k } else { ... key_hex = ...; &key_hex };
```

This two-step binding exists to work around the borrow checker.  It is valid
but unusual.  Since Rust 2021 the same can be expressed more cleanly by
returning an owned `String` from a helper method and calling `.as_str()` on the
result, rather than holding a `&str` into a local `String`.

### 2.3 `connect_reader` is a one-liner that just calls `connect_reader_mode`

```rust
fn connect_reader(ctx: &pcsc::Context, reader: &str) -> Result<pcsc::Card> {
    connect_reader_mode(ctx, reader, pcsc::ShareMode::Shared)
}
```

`connect_reader` has exactly one call site (`serial_from_reader`).  Inline it
or remove it — the wrapper adds no clarity.

### 2.4 `transmit_raw_card` vs `PcscSession::transmit_raw`

`transmit_raw_card` is a free function that does exactly what
`PcscSession::transmit_raw` does but accepts a `&pcsc::Card` directly (used
inside `put_data` where only a `Transaction` is available, not `self`).  The
duplication is necessary because `Transaction` derefs to `Card`, but the name
clash is confusing.  Rename `transmit_raw_card` to `transmit_card` or merge
the logic.

### 2.5 `encode_length` panics on oversized input

```rust
fn encode_length(len: usize) -> Vec<u8> {
    ...
    } else {
        panic!("length too large for BER encoding: {len}");
    }
}
```

All callers are internal and lengths are bounded by PIV object sizes, so a
panic is unlikely.  But `encode_length` could return `Vec<u8>` with a
3-byte `0x83` form for lengths > 0xFFFF, or the function signature could be
`-> Result<Vec<u8>>` to propagate the error.  A comment noting the max
supported object size would also suffice if a panic is intentional.

### 2.6 `#![allow(dead_code)]` on `auxiliaries.rs`

Several functions in `auxiliaries.rs` (`parse_admin_data`,
`get_pin_protected_management_key`) are only called under specific conditions
or feature flags, triggering the warning.  The blanket `#![allow(dead_code)]`
silences all warnings in the module.  Better options:
- Mark the truly unused functions `#[cfg(test)]` or `pub(crate)` with a note.
- Remove `#![allow(dead_code)]` and address each warning individually.

---

## 3. Opportunities for simplification

### 3.1 `VirtualState` stores `puk` but PUK unblock is not implemented

`puk` is stored in `VirtualState` and populated from fixtures, but no code ever
reads it.  Either implement PUK unblock or remove the field.

### 3.2 `SlotKey::generate` and `SlotKey::from_scalar_hex` share a constructor pattern

Both set `cert_der: None` and compute `public_point` identically.  A private
`SlotKey::from_secret(secret: SecretKey) -> Self` helper would remove the
duplication:

```rust
fn from_secret(secret: SecretKey) -> Self {
    let public_point = pubkey_to_uncompressed(&secret.public_key());
    Self { secret, public_point, cert_der: None }
}
```

### 3.3 `VirtualPiv::new` calls the three `default_*` functions instead of using `FixtureIdentity::default()`

`VirtualPiv::new` builds the state by calling `default_serial()`,
`default_reader()`, `default_version()` directly.  `FixtureIdentity` derives
`Default` and uses the same functions via `#[serde(default = "...")]`.  The
two code paths can diverge silently.  Unify by having `VirtualState::default_state`
consume a `FixtureIdentity::default()`.

### 3.4 `generate_certificate` in `virtual_piv.rs` generates a new key instead of using the slot's existing key

The `generate_certificate` method always calls `SlotKey::generate()` even if
the slot already holds a key from `generate_key`.  The hardware backend matches
this behaviour (it also generates a fresh key as part of certificate creation),
but the semantics are surprising: calling `generate_certificate` silently
replaces any previously generated key.  A comment explaining this intentional
design would prevent future confusion.

### 3.5 `harnessCommon` in `default.nix` has a redundant `buildInputs` assignment

```nix
harnessCommon = rustCommon // {
    nativeBuildInputs = ...;
    buildInputs   = rustCommon.buildInputs;  -- same as the merged value from //
    LIBCLANG_PATH = ...;
};
```

`rustCommon // { ... }` already carries `buildInputs` through the merge.  The
explicit `buildInputs = rustCommon.buildInputs;` line is a no-op.

### 3.6 `default.nix`: `harnessDeps` is a separate dep-only derivation but shares `rustCommon` source

`harnessDeps` uses `rustSrc` (the whole workspace filtered source), which means
a change to any file in `rust/` will invalidate both `rustDeps` and
`harnessDeps`, rebuilding them both.  This doubles the cold-build cost.
Consider whether `harnessDeps` could reuse `rustDeps` as a base (with
`cargoArtifacts = rustDeps`) rather than starting from scratch.

### 3.7 `serial_from_reader` and `version_from_reader` duplicate the SELECT PIV APDU

Both functions independently open a `pcsc::Card`, send the SELECT PIV APDU, and
then send their specific query APDU.  They could share a helper that opens a
session and returns a `PcscSession`, or at least share the SELECT byte literal
as a named constant.

---

## 4. Minor issues

### 4.1 Hardcoded cert validity dates

```rust
params.not_before = rcgen::date_time_ymd(2025, 1, 1);
params.not_after  = rcgen::date_time_ymd(2035, 1, 1);
```

Hardcoded in both `hardware.rs` and `virtual_piv.rs`.  The `not_before` date is
already in the past; `not_after` expires in 2035.  Consider computing
`not_before` from the current time and `not_after` as `not_before + N years`,
or at least make these constants.

### 4.2 `OBJ_PRINTED` constant defined three times

`0x5F_C109` appears as a constant or literal in `auxiliaries.rs`
(`pub const OBJ_PRINTED`), `hardware.rs` (`const OBJ_PRINTED`), and
`virtual_piv.rs` (`const OBJ_PRINTED` inside a function body).  Use the one
from `auxiliaries.rs` everywhere.

### 4.3 `encode_tlv` and `encode_length` are `pub(crate)` in `hardware.rs` but unused outside it

Both are marked `pub(crate)` but have no callers outside `hardware.rs`.  Drop
the visibility to private.

### 4.4 `pkcs8_der` borrow in `virtual_piv::generate_certificate`

```rust
let pkcs8_der = slot_key.secret.to_pkcs8_der()...?;
let key_pair = KeyPair::try_from(pkcs8_der.as_bytes())...?;
```

`pkcs8_der` is a `Zeroizing<Vec<u8>>` that is kept alive only to borrow
`.as_bytes()` for `key_pair`.  After `key_pair` is built, `pkcs8_der` is
dropped and the key material is zeroed.  This is correct, but the borrow and
drop order are easy to accidentally break during refactoring.  A comment noting
the intentional drop order would help.

### 4.5 `connect_reader_mode` appends `\0` and calls `CStr::from_bytes_with_nul`

```rust
let mut name = reader.to_owned();
name.push('\0');
let cstr = std::ffi::CStr::from_bytes_with_nul(name.as_bytes())...?;
```

This works but is awkward.  `CString::new(reader)` is the idiomatic way to
create a null-terminated string from a `&str`.
