<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# YubiKey NVM Internals — Research Notes

**Status:** complete — based on empirical experiments and public sources;
firmware internals are not publicly documented.

## 1. Hardware platform

The YubiKey 5 series runs on an **Infineon SLE78** secure microcontroller.

Key SLE78 characteristics (from Infineon product brief "Oracle's Java Card OS
on Infineon SLE 78", Edition 2, May 2018):
- **80 KB user memory** (NVM).
- **CC EAL6+** certified (hardware); CC EAL5+ (Oracle JavaCard OS layer).
- Supports Oracle **JavaCard 3.0.1 Classic** and GlobalPlatform 2.2.1.
- The chip *can* run the Oracle JavaCard VM — but Yubico uses their own
  proprietary firmware on the SLE78 for YubiKey 5, not JavaCard.
- NVM is word-addressable (16-bit words → 2-byte alignment minimum).
- Specific erase-block size and wear-leveling strategy are not publicly
  documented.

The early **YubiKey NEO** ran JavaCard on the SLE78 (or a predecessor chip),
so its EEPROM management was handled by the JavaCard runtime GC.  The
**YubiKey 5** runs Yubico's closed-source native firmware instead.

## 2. APDU-level object framing

Source: `yubico-piv-tool/lib/internal.h` (confirmed in `iqlusioninc/yubikey.rs`).

A PUT DATA command carries:

```
5C 03 XX XX XX       5 bytes  object-ID TLV  (tag 5C, len 03, 3-byte ID)
53 82 HH LL          4 bytes  data wrapper   (tag 53, 3-byte DER length)
[payload]            N bytes
```

Total APDU overhead = **9 bytes**.  Firmware APDU buffer = 3072 bytes.
Maximum storable payload = `3072 − 9 = 3063 bytes`.

```c
// yubico-piv-tool/lib/internal.h
#define CB_BUF_MAX_YK4   3072
#define CB_OBJ_MAX_YK4   (CB_BUF_MAX_YK4 - 9)   // = 3063
```

Empirically confirmed by `nvm_frag_test max-obj-size` on firmware 5.4.3.

The firmware stores the `53 L V` blob in NVM — i.e., it stores the tag,
the DER-encoded length, and the value.  For a 3063-byte payload the stored
blob is `53 82 0B F7 [3063 bytes]` = **3067 bytes** on-device (tag + 3-byte
length + payload).

## 3. PIV certificate object overhead ("the 3052 figure")

For a *certificate* stored via PUT DATA, the payload (the V in `53 L V`) is
itself a structured TLV:

```
70 82 HH LL [DER cert]   4 bytes overhead + N bytes DER   (cert tag)
71 01 00                  3 bytes                          (compression flag)
FE 00                     2 bytes                          (LRC tag)
```

Inner TLV overhead ≈ **9 bytes** (for large certs where the length needs
3 bytes).  So usable DER cert space = `3063 − 9 ≈ 3054` bytes.  Yubico
documentation rounds to "approximately 20 bytes of header data" (counting
from the 3072-byte buffer) and advertises **3052 bytes** as the maximum
certificate size.

Source: https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html

> "Certificates stored according to the PIV standard will have approximately
> 20 bytes of header data, including tag and length values, leaving 3052
> bytes for the certificate itself."

## 4. Total NVM capacity (measured)

| Quantity | Value |
|---|---|
| Gross NVM (Yubico spec) | 51,200 bytes |
| PIV applet overhead | 975 bytes |
| Available for data objects | **50,225 bytes** |
| Maximum single object payload | **3,063 bytes** (empirical) |

The 975-byte PIV overhead is consumed by: management key (24 bytes 3DES),
PIN/PUK counters and values, default CHUID and CCC objects, key-type
metadata for slots 9A/9C/9D/9E, and the internal object directory.

Measured on firmware 5.4.3 using `rust/yb-core/src/bin/nvm_frag_test.rs`.

## 5. Per-object NVM overhead (undocumented)

### Observation

Experiment: slot 0 shrunk from 3063-byte payload to 1-byte payload.
Payload delta = **3062 bytes**.  `free-nvm` probe immediately after found
only **3042 bytes** available — a **20-byte gap**.

The APDU/TLV framing is symmetric and does not explain the gap (both the old
and new allocations use a 3-byte DER length field in the `53` wrapper).

### Hypothesis

The firmware almost certainly stores a **per-object metadata record** in NVM
alongside the `53 L V` payload — for example a linked-list node containing
object ID, allocated size, and status flags.  This record is not part of
the `53 L V` content returned by GET DATA.

The observed 20-byte gap is consistent with such a per-object header.  At
2-byte word alignment on the SLE78, an 8-10 byte header rounded up to 10
bytes, combined with the 3067-byte stored blob rounded to the next word
boundary, could produce a 20-byte discrepancy.  However this is inference —
Yubico has not published the firmware's internal NVM allocator design.

### What is not publicly documented

- The YubiKey 5 firmware is closed-source.
- No public reverse engineering of the SLE78/YubiKey 5 NVM allocator exists.
- The Infineon SLE78 datasheet is not publicly available.
- No Hacker News, GitHub issues, or third-party tools expose per-object NVM
  overhead beyond the 9-byte APDU comment in `internal.h`.

## 6. Is there NVM fragmentation?

### The log-structured vs heap question

Flash memory cannot be overwritten in place; it must be erased at block
granularity.  Many embedded systems therefore use **log-structured storage**:
new writes append to a log, old versions are marked invalid, and a garbage
collector reclaims space.  Under this model there is no fragmentation —
free space is always recoverable.

An alternative is a **heap model**: objects are allocated from a pool and
freed in place, which can fragment over time if free blocks are too small
for large allocations.

**Which model does the YubiKey use?**  Not publicly documented.  However,
the reference JavaCard PIV implementation (OpenFIPS201, commissioned by the
Australian Department of Defence) uses a linked-list heap model:

```java
// PIV.java (OpenFIPS201)
// PERSISTENT - Data Store
private PIVDataObject firstDataObject;   // head of persistent linked list
```

Each `PIVDataObject` is a JavaCard persistent (EEPROM) object.  In JavaCard,
a `byte[]` array has a fixed size at allocation time; to "resize" content
you must allocate a new array and abandon the old one.  The JavaCard runtime
then garbage-collects the unreachable old array, reclaiming its EEPROM space.

The YubiKey 5 does **not** run JavaCard (unlike the YubiKey NEO), so this
architecture does not apply directly.  But Yubico's native firmware likely
uses an analogous model — either log-structured or a heap with GC — given
that our experiments consistently show no fragmentation.

Our experiments strongly suggest the YubiKey does **not** fragment in
practice:

### Experimental evidence (from `nvm_frag_test` and `self-test`)

| Test | Result |
|---|---|
| `frag-random` (100 random-size writes × 20 slots, then fill MAX) | Zero loss — see note below. |
| `frag-shrink1` (stress → shrink all to 1 byte → fill MAX) | Full capacity recovered. |
| `frag-delete` (stress → delete all → fill MAX) | Full capacity recovered. |
| `shrink0` + `free-nvm` | Shrinking slot 0 by 3062 bytes immediately freed 3042 bytes in a *different* slot — capacity transferred across slots with no loss (beyond the per-object overhead discussed above). |
| `self-test` (200 store/fetch/remove/list ops, NVM probed at format / after ops / after cleanup) | Free NVM after format = 49,535 B; after ops = 33,206 B; after cleanup = 49,535 B.  Delta = **+0 bytes**. |

**Note on `frag-random`:** the result was initially misread as −13,601 bytes
due to an accounting bug (residual sizes of stressed slots 14–19 were not
counted in the baseline).  After correcting the accounting the unaccounted
difference is zero — entirely explained by the partial last slot in the
binary-search probe (the probe fills slots until the first returns 0; the
last partial slot carries the remaining headroom tail, not a fragmentation
gap).

### Conclusion

The YubiKey 5 PIV applet **does not fragment NVM** under normal `yb`
workloads.  Whether this is because the firmware uses log-structured storage
with garbage collection, or because it uses a sophisticated heap compactor,
cannot be determined from public sources.

The 975-byte PIV applet overhead and the ~22-byte per-object overhead are
real and unavoidable, but they are fixed costs, not cumulative fragmentation.
Dynamic object sizing (spec 0010) is safe.

## 7. Open questions

- Does the SLE78 firmware use log-structured NVM with GC, or a heap model?
  This would explain both the no-fragmentation result and the per-object
  overhead.
- What exactly is the 20-byte per-object overhead?  Is it a fixed header,
  or does it vary with object size (alignment padding)?
- Is the 3,063-byte max payload stable across firmware versions, or only
  measured on 5.4.3?
- Does the ~975-byte PIV overhead vary with the number of keys/certificates
  stored in standard slots (9A–9E)?

## 8. What was searched and not found

The following searches returned no useful results:

- GitHub: no public repositories discuss YubiKey NVM fragmentation.
- Hacker News (via Algolia): no discussions about YubiKey NVM internals or SLE78.
- Yubico technical manual pages: cover only application-level capacity numbers
  (e.g., "25 FIDO2 resident keys", "64 OATH credentials"); no NVM architecture.
- Infineon SLE78 datasheet: not publicly available.
- Infineon SLE78/Oracle JavaCard OS product brief: marketing document only;
  confirms 80 KB NVM, JavaCard 3.0.1, CC EAL6+, but contains no information
  about NVM allocator internals, log-structured storage, or fragmentation.
  URL: https://www.infineon.com/dgdl/Infineon-Oracle's_Java_Card_Operating_System_on_Infineon_SLE_78-PB-v01_00-EN.pdf
- Reddit: `reddit.com` is blocked by the fetch tool.
- JavaCard VM spec (Oracle): landing page only; full spec requires download.
- NCC Group YubiKey retrospective: redirected away (307).
- EclipseCon JavaCard NVM/EEPROM management talk: redirected away (302).

## 9. References

- `rust/yb-core/src/bin/nvm_frag_test.rs` — empirical measurement program
- `rust/yb/src/cli/self_test.rs` — NVM-instrumented self-test (measures free NVM at format / after ops / after cleanup)
- `docs/specs/0010-dynamic-object-sizing.md` — implemented spec; dynamic object sizing
- `docs/specs/0016-pre-allocated-tiered-store.md` — suspended spec (fragmentation premise was false)
- [yubico-piv-tool/lib/internal.h](https://github.com/Yubico/yubico-piv-tool/blob/master/lib/internal.h) — `CB_OBJ_MAX = CB_BUF_MAX - 9 = 3063`
- [iqlusioninc/yubikey.rs consts.rs](https://github.com/iqlusioninc/yubikey.rs) — independent Rust confirmation of same constants
- [Yubico: Maximum certificate sizes](https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html) — "~20 bytes header, 3052 bytes for cert"
- [Yubico: PIV data objects](https://docs.yubico.com/yesdk/users-manual/application-piv/piv-objects.html) — "at most approximately 3,052 bytes per object"
- [Yubico: PIV GET and PUT DATA](https://docs.yubico.com/yesdk/users-manual/application-piv/get-and-put-data.html)
- [OpenFIPS201 PIV applet — PIV.java](https://github.com/makinako/OpenFIPS201/blob/main/src/com/makina/security/openfips201/PIV.java) — linked-list data store, JavaCard GC
- [Infineon SLE78 / Oracle JavaCard OS product brief](https://www.infineon.com/dgdl/Infineon-Oracle's_Java_Card_Operating_System_on_Infineon_SLE_78-PB-v01_00-EN.pdf?fileId=5546d462636cc8fb0163ef8124927144) — 80 KB NVM, JavaCard 3.0.1, CC EAL6+; no allocator details (see `infineon-oracles-java-card-operating-system-on-infineon-sle-78-pb-en.pdf`)
