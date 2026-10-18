<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Invariants

The guarantees yb documents: data safety, write ordering, security.  One
file per invariant, `NNNN-title.md`: the statement, why it matters, where
the code keeps it, its limits, and its **regression tests**, which fail
if the invariant breaks.  `scripts/check-invariants` checks that every
test named there exists.

| # | Invariant |
|---|---|
| [0001](0001-interrupted-writes-lose-nothing.md) | Interrupted Writes Lose Nothing |
| [0002](0002-reads-never-write.md) | Reading Never Writes |
| [0003](0003-only-complete-chains-are-visible.md) | Only Complete Blobs of the Store Are Visible |
| [0004](0004-a-store-that-does-not-fit-writes-nothing.md) | A Store Refused for Room Writes Nothing |
| [0005](0005-existing-stores-stay-readable.md) | Existing Stores Stay Readable |
| [0006](0006-tampering-is-detected-before-use.md) | Tampering Is Detected Before Use |
| [0007](0007-commands-act-only-on-the-selected-yubikey.md) | Commands Act Only on the Selected YubiKey |
| [0008](0008-format-never-strands-blobs.md) | Format Never Strands Blobs |
| [0009](0009-management-key-is-never-lost.md) | The Management Key Is Never Lost |
| [0010](0010-no-secrets-behind-factory-credentials.md) | No Secrets Behind Factory Credentials |
| [0011](0011-errors-reveal-no-identity-or-secret.md) | Errors Reveal No Identity or Secret |
| [0012](0012-simulated-yubikey-only-in-test-builds.md) | A Simulated YubiKey Only in Test Builds |
| [0013](0013-management-key-held-in-zeroizing-memory.md) | The Management Key Is Held in Zeroizing Memory |
| [0014](0014-older-yb-never-writes-a-post-quantum-store.md) | Older yb Never Writes to a Post-Quantum Store |
| [0015](0015-management-key-is-checked-before-every-write-and-fetch.md) | The Management Key Is Checked Before Every Write and Fetch |
| [0016](0016-a-post-quantum-store-exists-once-its-descriptor-is-written.md) | A Post-Quantum Store Exists Only Once Its Descriptor Is Written |
| [0017](0017-the-fido2-pin-is-not-tried-with-few-attempts-left.md) | The FIDO2 PIN Is Not Tried With Few Attempts Left |
| [0018](0018-release-files-are-built-tested-and-approved.md) | Release Files Are Built, Tested and Approved |
| [0019](0019-unencrypted-blobs-are-readable-without-any-pin.md) | Unencrypted Blobs Are Readable Without Any PIN |
| [0020](0020-operations-are-serializable.md) | yb's Operations Are Serializable |
| [0021](0021-a-snapshot-never-plans-a-write.md) | A Snapshot Never Plans a Write |

## Not guaranteed

Stated here so that no document claims them:

- **Rollback protection:** a whole store restored to an older, genuinely
  signed state cannot be detected by the YubiKey alone (spec 0033).
- **Forward secrecy:** blobs stay decryptable by the store's slot key;
  rotating it is spec 0035 (pending).
- **Post-quantum stores against a recording of the USB traffic:** CTAP
  protects the FIDO2 PIN and the `hmac-secret` values on the USB link
  with ECDH P-256, which a future quantum computer could break from a
  recording (spec 0028, "Threat model").
- **Rollback in post-quantum stores:** a blob replaced by an older
  genuine version of itself, or a whole store restored to an older
  state, is not detected (spec 0028 non-goal); writing either needs the
  management key, or a PIV reset, which invariant 0015 detects.
- **Secrets off command lines:** the deprecated `--pin` and `--key`
  options still accept them (spec 0034 non-goal), and `yb self-test`
  passes its own test PIN to its children as `YB_PIN`.

## Adding one

Copy an existing file, take the next number, list at least one
regression test that fails without the invariant (check it by breaking
the code on purpose), and add a row above.
