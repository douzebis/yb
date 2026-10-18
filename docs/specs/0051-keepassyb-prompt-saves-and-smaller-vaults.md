<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0051 — KeePassYB: Prompt Saves and Smaller Vaults

**Status:** implemented
**App:** KeePassYB (`douzebis/keepassyb`, branch `keepassyb`); yb (`yb fsck`)
**Implemented in:** 2026-10-18

## Problem

- **Saves come late:** a vault on a YubiKey is saved 10 s after the last
  change (spec 0050 S2).  The PIN prompt and the touch then come long
  after the edit that needs them, which feels unnatural.
- **Vaults take more room than their content:**
  - KeePassXC adds 64 to 512 random bytes to every save (about 290 bytes
    once compressed, 10% of a 3 KB vault).  It defends a vault shared
    with KeeShare against an attacker who sees its size (KeePassXC
    commit `72fc0069`); a vault without KeeShare gains nothing from it;
  - KeePassXC keeps up to 10 old versions of each entry.
- **`yb fsck` reads unevenly:** "ok (3/3 tries left)" for the PIV PIN,
  "set, 8 tries left" for FIDO2's; "(checksums need no PIN)"; a
  two-line hint; "NVM".

## Goals

- A vault on a YubiKey is saved about 0.25 s after the last request.
- Its written copy has no padding unless the vault uses KeeShare; its old
  versions are not kept by default.
- `yb fsck` says the same things the same way.

## Non-goals

- **File databases:** unchanged.
- **The view state** (which groups are expanded, the selected and top
  visible groups): written as KeePassXC writes it (see "Considered and
  dropped").
- **Vaults already on a YubiKey:** their history setting is theirs.

## Specification

### S1. Saves 0.25 s after the last request

- **The quiet delay** (spec 0050 S2) becomes 0.25 s after the last of:
  - **a change** (the end of a user input: OK in the entry editor, a
    deletion, a move); KeePassXC reports it 150 ms after the change, so
    the timer runs 100 ms from that report;
  - **the end of a YubiKey operation** (a read, a refresh, a write): no
    save starts during one, nor within 0.25 s of its end;
  - **a request to save** (Save, Ctrl+S): it joins the same delay, so a
    burst of saves makes one write.
- **Lock, close and exit** save at once: they need the outcome before
  going on.  So do Retry (spec 0047's dialog) and KeePassXC's merge.
- Unchanged from spec 0050: nothing is written when the normalized
  content did not change; a failed automatic save waits for the next
  change.

### S2. No padding without KeeShare

- A vault none of whose groups is shared through KeeShare is written to
  the YubiKey without KeePassXC's random padding (`KPXC_RANDOM_SLUG`):
  any padding read with it is dropped.
- A vault with a shared group keeps it, unchanged.

### S3. No history by default on a YubiKey

- When a vault is first saved to a YubiKey (a new vault, or Save As from
  a file), its history setting (Database settings → History) becomes 0
  versions, and the old versions it holds are dropped from it.  The user
  is told so, and may raise the setting.
- A vault already on a YubiKey keeps its setting.

### S4. `yb fsck`'s wording

- **PINs and PUK:** state first, then `n/max tries left`, no
  parentheses; states `set`, `factory default` (a warning), `blocked`
  (an error): `set, 3/3 tries left`.  FIDO2's maximum is 8 (CTAP 2).
- **The management key:** the state first: `set, AES-192, kept on the
  YubiKey (PRINTED), unlocked by the PIV PIN`, or `factory default,
  3DES`.
- **The store's management key:** `a copy, wrapped by FIDO2 (AES-192),
  not checked (needs the FIDO2 PIN)`.
- **Integrity:** `2 checksums OK, 0 corrupted`, without "(checksums need
  no PIN)".
- **Not checked:** one line, `credential, management key, seals — check
  with \`yb fsck --seals\` (needs the FIDO2 PIN)`, then a blank line.
- **The memory line:** `YubiKey memory: ~3157 bytes used by the store,
  ~318 bytes by other data, ~47725 bytes free (estimated)`.

## Tests

- KeePassYB: the 0.25 s delay restarted by a change, a YubiKey operation
  and a save request; lock saves at once; no padding without KeeShare,
  padding kept with it; history 0 when first saved to a YubiKey, kept
  when already there.
- yb: the report's tests follow the new wording.

## Implementation notes (2026-10-18)

- KeePassYB: `DatabaseWidget::saveSoon` (Save on a vault on a YubiKey,
  through `DatabaseTabWidget::saveDatabase`); the timer waits while
  `DeviceStorage::busy()` and for 0.25 s after
  `DeviceStorage::msSinceLastOperation()`, which every operation updates
  (`offGui`), a listing included.
- A failed automatic save marks the vault modified again, and so does
  the padding's change: "until the next change" is decided on the
  content, not on the modified signal.  The normalized content's hash is
  kept at the failure, and an automatic save is tried again only once it
  differs.
- The padding test: KeeShare's key (`KeeShare/Reference` in a group's
  custom data), read by the core without depending on KeeShare.
- yb: the legacy store's integrity line loses its "(signatures need no
  PIN)" too; "checksum" or "checksums" by the count.

## Considered and dropped

- **Leaving the view state out of the written copy:** a KDBX vault is an
  XML document, compressed then encrypted; the view state is a few text
  fields (`IsExpanded` per group, `LastSelectedGroup`,
  `LastTopVisibleGroup`).  Writing them as defaults saves about 25 bytes
  (two UUIDs that compress to almost nothing, `False` being no shorter
  than `True`); leaving them out, a few bytes more, as gzip already
  compresses the repeated names.  Encryption rounds to 16-byte blocks and
  yb stores blobs in objects of about 3 KB, so the gain is nil in
  practice, against groups coming back collapsed at every opening.

## References

- [spec 0047](0047-keepassyb-and-a-slow-yubikey.md): the progress
  dialog, the unchanged-content check.
- [spec 0050](0050-keepassyb-snapshots-and-automatic-saves.md):
  automatic saves (S2 changed here).
- [spec 0045](0045-yubikey-report-by-application.md): `yb fsck`'s report.
- KeePassXC commit `72fc0069` (2024): the random padding.
