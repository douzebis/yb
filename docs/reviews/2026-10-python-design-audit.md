<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Audit of the Python-era design document (2026-10-13)

The design document of the Python implementation (`doc/DESIGN.md`,
deleted with that implementation in `4eb307a`, 2026-03-21) is restored as
`docs/archive/python-DESIGN.md`.  This audit checks each of its points
against the current Rust code and specs (working tree of 2026-10-13, i.e.
`main` at `67a125d` plus the uncommitted spec 0031 work).

Method: three read-only reviews (document lines 1–792, lines 794–1675,
and a git-history search for past interruption tests), followed by spot
checks.  Findings marked **(verified)** were re-checked by hand against
the code or history; the others rest on the reviews' reading, with the
references given, and should be confirmed when acted upon.

## Status legend

- **Aligned** — still true.
- **Changed, recorded** — differs, and a spec, commit or doc says why.
- **Diverged, unrecorded** — differs, and nothing says why: the findings
  that matter.
- **Never true** — a claim the Python implementation did not meet either.
- **Obsolete** — Python-only (tooling, file layout), replaced.

## 1. Findings, by severity

### 1.1 Data loss and correctness

1. **Replace overwrote the stored copy in place (verified).**  The port
   (`6c7fc97`, 2026-03-20) made `store_blob` free the old copy before
   allocating, so a YubiKey pulled out mid-replace could lose both copies.
   The document described this exact pattern as unsafe ("Unsafe: Overwrite
   With Index Reuse") and recommended copy-on-write and body-first writes.
   *Fixed in the working tree by spec 0031; 8 regression tests, which fail
   on the old code.*
2. **`sanitize()` lost its chain validation, and stopped running before
   every operation (verified).**  The document's protections: age and
   position sequence, pointers in range, no cycles, and "sanitize runs
   before every operation".  The Rust port kept only de-duplication and
   reachability, and only `store` and `remove` sanitized.  *Restored by
   spec 0031, but with a weaker age rule; see 3.*
3. **Spec 0031's age rule rests on a false premise (verified).**  It
   requires only `age >= head.age`, "because Python gave all chunks the same
   age".  Python gave consecutive ages (`store_age + 1`, raised after each
   chunk by `commit_object`), and so does Rust (signature spill chunk
   included).  The strict rule `age == head.age + chunk_pos` costs nothing
   and closes a narrow case where a leftover head from a pre-0031
   interrupted write could be completed by another blob's chunk and come
   back with wrong bytes.
4. **`yb store`'s capacity check contradicts the replace rule
   (verified).**  `yb/src/cli/store.rs` counts the old copy as "freed
   before new ones are allocated"; `store_blob` requires room for both.
   Near capacity, `yb store` passes its check, then fails with "store is
   full while writing … — this should not happen"; with several files,
   the earlier ones are already written, which breaks the all-or-nothing
   promise.  No data loss.  The mismatch predates spec 0031.  The signature
   spill chunk is counted by neither check.
5. **`yb rm` bypasses `remove_blob` (verified).**  `cli/remove.rs` resets
   the chains itself and syncs in index order.  Safe today only because a
   blob's head always has the lowest index of its chain; the spec 0031
   tests exercise `remove_blob`, not this path.
6. **`yb fsck` can panic on a corrupt store.**  `Store::chunk_chain` does
   not range-check `next_chunk`, and fsck walks chains on the raw store
   (`cli/fsck.rs:127`).  A pointer beyond `object_count` crashes the
   diagnostic tool when it is most needed.  Spec 0031's text also says fsck
   sees the sanitized store; the code (rightly) gives it the raw one.
7. **`yb self-test`'s free-space probe uses the first reader, not the
   selected one** (`self_test.rs:219-225`), and fills then clears every
   empty yb object; an error mid-probe skips the clean-up.  With several
   YubiKeys connected, it can write to one the user did not select.
8. **`yb self-test` masks errors:** any failed `fetch` counts as "not
   found", any failed `rm` as "not found", any message containing "store
   is full" as a valid full store (`self_test.rs:119-137`).  It also uses
   capacity 25 for 20 objects (spec 0015 says 15), so the masked "store is
   full" path of finding 4 is hit often.

### 1.2 Security claims that were never true

The document makes three promises that neither implementation kept.  They
are not repeated in current docs, but must not be carried over:

- **"Replay attacks (age-based freshness)"** — ages are writable by anyone
  with the management key, and the blob signature (spec 0017) covers the
  payload only, not the name, age or slot: rolling back to an older image,
  swapping blobs between names, or replacing a blob with an unsigned one
  go undetected (fetch does not verify signatures; `ls` shows an unsigned
  blob as "unverified", not corrupted).
- **"Forward secrecy: fresh ephemeral key per store"** — the scheme is
  ephemeral-static ECDH: whoever obtains the slot key decrypts every blob.
- **"The management key never leaves the YubiKey"** — when kept on the
  YubiKey, yb reads it into host memory to authenticate, and holds it in
  plain `String`s (not zeroized).

Related, lower: a store whose signing fails, or that has no room for the
signature's spill chunk, stores the blob unsigned with only a warning.

### 1.3 Other divergences, unrecorded (lower severity)

- `yb self-test` passes the management key, possibly unwrapped from the
  PIN-protected PRINTED object, in the environment of its child processes;
  the deprecated `--key` flag still accepts it on the command line.
- `YB_FIXTURE` makes the release binary use a simulated card described in a
  file (used by `yb_cli_tests`): an environment variable can redirect yb
  away from the real YubiKey.  To be assessed.
- No overflow guard on ages (24-bit; a wrapped age of 0 looks like an empty
  slot; Python asserted the bound).  Theoretical (about 16 million writes).
- Objects' `object_count` is no longer cross-checked against object 0.
- `yb fetch` asks for the PIN even for unencrypted blobs.
- `self-test`: no timeout on child processes, `--quiet` ignored, stores
  without `--no-compress` (spec 0015 says otherwise).
- The legacy AES-CBC decryption path (pre-spec 0006 blobs) is still
  reachable: unauthenticated ciphertext is accepted when it carries the
  CBC header.

### 1.4 Stale documentation and spec statuses

- **Spec 0020**'s title ("Remove bash completion patches from Nix
  packaging") and status ("implemented") read as if the patches were
  removed; they are still in `package.nix`.  That is the spec's recorded
  outcome, not a divergence: its investigation (2026-05-05) found both
  patches necessary (the dynamic completion engine lacks `clap_complete`'s
  static-generator fixes), upstreamed patch 2 (clap PR #6364, still open as
  of 2026-10-13; issue #6363 closed as a duplicate of #6280), and kept
  patch 1 pending an upstream design.  Only the wording misleads
  **(verified)**.  (An earlier version of this audit wrongly reported the
  spec as stale.)
- **Spec 0006** is "ready" although implemented; **spec 0031** is
  "in-progress".
- `rust/docs/DESIGN.md` still describes the pre-0031 store (step "Delete
  any existing blob", `remove` with a plain `sync`, no complete-chain
  rule) and a default of 20 objects (the code says 32).
- `docs/test-harness.md` says self-test formats 16 objects; spec 0015 and
  the code say 20.
- The archived document itself was wrong in places even for Python: key
  slot default `0x9e` (Python used `0x82`), ADMIN DATA bit meanings.

## 2. Testing: what existed, and what exists now

**Interruption ("rip") testing existed** (verified): the Python
`EmulatedPiv(ejection_probability, seed)` failed random object writes, and
`test_with_ejection_simulation` (`cdf2974`, 2025-11-16) ran 2,000 random
store, replace, remove, fetch and list operations at 20% ejection, checking
the state after reconnecting.  Its blind spot: after an interrupted
replace, it accepted "rolled back" without fetching the old content.  It
was deleted with the Python tree (`4eb307a`) and never ported; a dead,
unseeded `EmulatedPiv::with_ejection` remains in
`rust/yb-core/src/piv/emulated.rs`.

| Property | Python era | Now |
|---|---|---|
| Store, replace, remove survive an interruption | random ejections, partial check | spec 0031 tests: every write of 6 scenarios, old and new content checked (uncommitted) |
| Interruption during `format`, key rotation | — | `Fault::WriteFails` tests in `yb/tests/cli_tests.rs` |
| Long random operation sequences | 10,000 operations, store reloaded each time | 300 operations, never reloaded from the card |
| Random sequences **with** interruptions | yes | **missing** |
| Interruption with encryption, compression, signature spill, multi-file store, `yb rm` | — | **missing** |
| Commands reach the selected YubiKey when several are connected | `test_multiple_devices` | **missing** |
| "Store is full" is genuine | checked | accepted without check (tier-1 and self-test) |
| Sanitize: incomplete chains, cycles | — | only duplicates and orphans tested |

## 3. Point-by-point tables

### Lines 1–792: architecture, format, resilience, commands, security

| Doc lines | Claim | Status | Evidence |
|---|---|---|---|
| 25–26, 749 | 16 objects, ~3 KB each, ~36 KB | Changed, recorded | 32 objects default (`constants.rs:29`, spec 0023); dynamic sizing (0010); NVM-bound |
| 27–28, 41–193 | Click, Python modules, yubico-piv-tool, ykman | Obsolete | clap; native PC/SC APDUs |
| 89–95 | Six commands | Changed, recorded | + rotate-management-key (0027), list-readers, select (0013), self-test (0015) |
| 104–130 | Store, object layout, chain, head metadata, magic | Aligned | `store/mod.rs`, `constants.rs` (byte-identical offsets); + compression bit (0012), signature trailer (0017) |
| — | `object_count` checked on every object | Diverged, unrecorded (low) | not checked in `from_device_raw` |
| 139–141 | Ephemeral ECDH P-256, HKDF-SHA256 | Aligned | `crypto.rs` |
| 142–152, 610–613 | AES-256-CBC, random IV, PKCS#7 | Changed, recorded | AES-256-GCM (spec 0006); CBC decrypt-only |
| 156 | Key slot default 0x9e | Never true | Python and Rust use 0x82 |
| 162, 606 | Forward secrecy | Never true | ephemeral-static ECDH |
| 164 | Encryption not authenticated | Changed, recorded | GCM (0006) + signature (0017) |
| 210, 327–328 | Sanitize before every operation | Aligned (working tree) | spec 0031 |
| 220–227 | Free allocation, consecutive ages, sync | Aligned / changed (0031 write order) | `orchestrator/mod.rs` |
| 246 | PIN only for encrypted blobs | Diverged, unrecorded (low) | `cli/fetch.rs:72` |
| 276–297 | Magic `0xF2ED5F0B`, registered with `file` | Aligned (code); registry unverified | `constants.rs:13` |
| 307–308, 441–442 | Consecutive ages and positions | Weakened by spec 0031 on a false premise | finding 1.1.3 |
| 313–315 | One blob per name, newer wins | Aligned | `sanitize` |
| 321–475 | Resilience: safe allocation, write order, recovery | Aligned in the working tree (0031); broken on `main` since the port | finding 1.1.1 |
| 486–584 | Command options and outputs | Changed, recorded | specs 0007, 0010, 0012, 0018, 0022, 0023 |
| 593–601 | Threat model: data at rest; not physical tampering, malware, side channels | Aligned | spec 0006 |
| 595 | Replay protection | Never true | finding 1.2 |
| 616–637 | PIN requirements, default credentials, `ykman --protect` | Changed, recorded | specs 0017, 0021, 0024, 0027 |
| 642–648 | ADMIN DATA bits, PRINTED layout | ADMIN DATA wrong in the doc; PRINTED aligned and extended | spec 0021 §4, spec 0022 |
| 697–708 | `--key`, `--pin` flags | Changed, recorded | hidden and deprecated; `YB_MANAGEMENT_KEY`, `YB_PIN`, `--pin-stdin` |
| 713 | Management key never leaves the YubiKey | Never true | finding 1.2 |
| 746–748 | CBC padding oracle; no key rotation; one key per store | Mostly changed (0006, 0027); storage-key rotation still missing | — |
| 755–790 | Dependencies, no tests yet | Obsolete / changed | RustCrypto, pcsc; tier-1 and tier-2 tests |

### Lines 794–1675: investigations, testing, self-test

| Doc lines | Claim | Status | Evidence |
|---|---|---|---|
| 798–943 | FIDO2 touch selection (investigation) | Obsolete; picker done | spec 0013 |
| 949–1135 | Management key handling: subprocess exposure, `mlock` | Changed (in-process, `Zeroizing` in places); `mlock` not done | `context.rs`; finding 1.3 |
| 1179–1183 | Each operation loads, sanitizes, acts, syncs | Aligned for the CLI; the random test never reloads | `virtual_piv_tests.rs:613-664` |
| 1200–1202 | Seeded emulator ejection | Diverged: dead and unseeded | `emulated.rs:44, 89-93` |
| 1229–1287 | 10,000-operation test, ejections, two-state check | Partly replaced (300 operations; 0031 deterministic interruption tests) | section 2 |
| 1293–1311 | 512-byte objects, size mix up to 20 KB | Obsolete / changed (16 KB max) | spec 0010, `test_utils.rs` |
| 1341–1368 | Duplicates resolved; generator; toy filesystem; comparisons | Aligned, except "store full" no longer verified | spec 0014 |
| 1380–1411 | PKCS#11 token selection fix | Obsolete (bug class removed), untested | finding: no multi-device routing test |
| 1415–1444 | Shell completion | Aligned / changed (spec 0020) | `complete.rs` |
| 1469–1600 | Self-test: purpose, flow, error handling, capacity | Partly aligned; masking and probe issues | findings 1.1.7, 1.1.8 |
| 1605–1659 | File layout, external references | Obsolete | — |
| 1673 | Age increases once per store | Changed: once per object | spec 0031 |

## 4. How this happened, in one paragraph

The resilience property lived in this document's prose, not in tests or
next to the code.  The port's spec (0001) defined success as wire-format
compatibility and command-line parity, and its tests checked exactly that.
The document was deleted the next day with the Python tree, and only a
one-line summary reached `rust/docs/DESIGN.md`.  Nothing then stood between
an "obvious" replace (free the old copy, then write the new one) and the
regression.  The same mechanism explains the other unrecorded divergences:
what was neither specified, tested nor commented at the decision point was
not preserved.
