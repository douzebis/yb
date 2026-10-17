<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0042 — `file` Magic for Post-Quantum Stores

**Status:** draft
**App:** docs (submission to the `file` project, outside yb)
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

Post-quantum stores (spec 0028) use a new magic, `0xF2EDF0B2`, in
every object.  The `file` magic database knows only the legacy magic
`0xF2ED5F0B`: it was registered by
[bug #666](https://bugs.astron.com/view.php?id=666), opened 2025-06-02,
merged 2025-06-08 by Christos Zoulas, and shipped in file 5.47.

So a dump of a post-quantum store's object shows as `data`.  An empty
chunk of a 16-object store is even misnamed `GLS_BINARY_LSB_FIRST`: an
SGI rule, `4 belong 0x10000000`, matches its bytes 4–7.

```shell
$ file descriptor.bin empty-chunk.bin
descriptor.bin:  data
empty-chunk.bin: GLS_BINARY_LSB_FIRST
```

Spec 0028 lists the registration among its release tasks.
`docs/YBLOB_FORMAT.md` §11.5 says "not yet in the `file` database".

## Goals

- G1. Submit a rule for `0xF2EDF0B2` to the `file` project, in the form
  that worked for bug #666: a short report with a patch against
  `magic/Magdir/filesystems`.
- G2. The rule tells apart the store descriptor (its version and chunk
  count shown) from chunks (in use or empty).
- G3. The rule is tested before submission, compiled into upstream's
  full database, on the objects of a real post-quantum store and on
  counter-examples.
- G4. Once the rule is merged, yb's documentation says so, with the
  `file` version that ships it.

## Non-goals

- Changing the legacy entry, for example to show its details too.  It
  works; a separate patch can do that later if wanted.
- Other registries: freedesktop.org's shared-mime-info, IANA media
  types.  These are not needed for raw object dumps.
- yb itself using libmagic.

## Specification

### The rule

It is appended after the existing yblob entry, at the end of
`magic/Magdir/filesystems`, in the same style.

```
# YBLOB post-quantum object storage
# The same storage, protected by the FIDO2 application (hmac-secret)
# https://github.com/douzebis/yb (docs/YBLOB_FORMAT.md, section 11)
0    lelong    0xF2EDF0B2    yblob post-quantum object store image data
>5   ubyte     1             \b, store descriptor
>>6  ubyte     x             \b, version %u
>>4  ubyte     x             \b, %u chunks
>5   ubyte     0             \b, chunk
>>9  ubyte     x             \b, in use
>>9  default   x             \b, empty
```

How each line follows `docs/YBLOB_FORMAT.md` §11:

- **Bytes 0–3:** `MAGIC`, little-endian, in every object.
- **Byte 5:** the object's type.  The descriptor has `TYPE = 0x01`; a
  chunk has `0x00` there (no store key slot).
- **Descriptor:**
  - byte 6 is `VERSION`;
  - byte 4 is `OBJECT_COUNT`, the number of chunks.
- **Chunk:** an empty chunk is exactly 9 bytes (§2, "Object size"),
  while a chunk in use is at least 12.  So byte 9 exists only in a chunk
  in use, and `default` reports the empty case.

In the compiled database the rule's strength is 70 and the SGI rule's
is 40, so an empty chunk is named correctly (see "Tests").

### The patch

It is made against upstream's current tree (GitHub mirror `file/file`,
commit `4ee5ca8`):

```diff
--- a/magic/Magdir/filesystems
+++ b/magic/Magdir/filesystems
@@ -2792,3 +2792,14 @@
 # PIN-protected storage format based on the PIV application
 # https://github.com/douzebis/yb
 0    lelong    0xF2ED5F0B    yblob object store image data
+
+# YBLOB post-quantum object storage
+# The same storage, protected by the FIDO2 application (hmac-secret)
+# https://github.com/douzebis/yb (docs/YBLOB_FORMAT.md, section 11)
+0    lelong    0xF2EDF0B2    yblob post-quantum object store image data
+>5   ubyte     1             \b, store descriptor
+>>6  ubyte     x             \b, version %u
+>>4  ubyte     x             \b, %u chunks
+>5   ubyte     0             \b, chunk
+>>9  ubyte     x             \b, in use
+>>9  default   x             \b, empty
```

Attach it as `yblob-pq-file.patch`.  If upstream has moved by the time
of submission, regenerate it against the new tree; the hunk only
appends.

### The report

Submitted at <https://bugs.astron.com/> by the reporter account
`douzeb`, with the same fields as bug #666:

| Field | Value |
|---|---|
| Project | file |
| Category | General |
| Severity | feature |
| Reproducibility | N/A |
| Platform | Linux |
| Summary | Add YBLOB post-quantum object storage format support |

Description:

> This patch adds support for the post-quantum variant of the YBLOB
> mini object storage format (bug #666 added the original one, magic
> 0xF2ED5F0B).
>
> The variant stores the same kind of sensitive blobs in the PIV
> application's custom objects, but protects them with the YubiKey's
> FIDO2 application (hmac-secret) instead of PIV keys.  Every object
> starts with the new magic 0xF2EDF0B2.  The rule tells the store
> descriptor (version, chunk count) from chunks (in use, or empty: an
> empty chunk is exactly 9 bytes).
>
> Tested by compiling the patched Magdir with file -C, on the 17 objects
> of a real store, on a legacy store object and on random data:
>
>     descriptor.bin: yblob post-quantum object store image data, store descriptor, version 1, 16 chunks
>     chunk00.bin:    yblob post-quantum object store image data, chunk, in use
>     chunk01.bin:    yblob post-quantum object store image data, chunk, empty
>     legacy.bin:     yblob object store image data
>     random.bin:     data
>
> Without the patch, an empty chunk of a 16-object store shows as
> GLS_BINARY_LSB_FIRST (Magdir/sgi, 4 belong 0x10000000); the new rule
> is stronger (70 vs 40).
>
> Format: https://github.com/douzebis/yb/blob/main/docs/YBLOB_FORMAT.md
> (section 11).

No sample files are attached: bug #666 needed none.  If they are asked
for, attach the descriptor, a chunk in use and an empty chunk, made as
in "Tests".  They hold only a throwaway emulator credential and test
data.

### After the merge

- `docs/YBLOB_FORMAT.md` §11.5: the rule, the bug number, and the `file`
  version that ships it (as §9 does for the legacy magic).
- `README.md`, "File Format Recognition": mention both magics.
- Spec 0028, release tasks: mark the `file` magic task done.

## Invariants

None: documentation and an external registration only.

## Tests

Done before submission, and to redo if the rule changes:

1. **A real post-quantum store,** made with the FIDO2 emulator: the
   test fixture of `yb-fido2-emulator/tests/yubiblob_tests.rs`, 16
   chunks, one blob stored.  Its 17 objects come out of the simulated
   card's file (`objects`, hex) into one `.bin` file each.
2. **Counter-examples:**
   - a legacy store object (magic `0xF2ED5F0B`), which must keep its
     own name;
   - 300 random bytes, which must stay `data`.
3. **Upstream's `magic/Magdir` at the commit of the patch,** with the
   patch applied, compiled with `file -C -m Magdir`: no warnings for
   `filesystems`.
4. **`file -m Magdir.mgc` on every sample:**
   - the descriptor;
   - the chunk in use;
   - the 15 empty chunks;
   - the legacy object;
   - the random data.
   The results are those quoted in the report.
5. **`file -l` on the compiled database:** our rule at strength 70,
   `GLS_BINARY_LSB_FIRST` at 40.

Result (file 5.48 tools, upstream `4ee5ca8`): as in the report.

## Open questions

None.

## References

- [Bug #666](https://bugs.astron.com/view.php?id=666): the legacy magic
  (file 5.47).
- [spec 0028](0028-post-quantum-protection.md): post-quantum stores;
  release tasks.
- `docs/YBLOB_FORMAT.md`: §9 (legacy magic), §11 (post-quantum stores),
  §2 (object sizes).
- `file` project: <https://github.com/file/file> (mirror),
  <https://bugs.astron.com/> (issues), magic(5).
