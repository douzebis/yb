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

## Not guaranteed

Stated here so that no document claims them:

- **Rollback protection:** a whole store restored to an older, genuinely
  signed state cannot be detected by the YubiKey alone (spec 0033).
- **Forward secrecy:** blobs stay decryptable by the store's slot key;
  rotating it is spec 0035 (pending).
- **Secrets off command lines:** the deprecated `--pin` and `--key`
  options still accept them (spec 0034 non-goal), and `yb self-test`
  passes its own test PIN to its children as `YB_PIN`.

## Adding one

Copy an existing file, take the next number, list at least one
regression test that fails without the invariant (check it by breaking
the code on purpose), and add a row above.
