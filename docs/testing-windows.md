<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Testing yb on Windows With a Real YubiKey

CI tests yb on Windows against a simulated YubiKey only.  This checklist
covers what only a real one shows: Windows' smart-card stack (reader
names, its own smart-card driver, its plug-and-play service), the
console, and libyubiblob built by MSVC.

One full pass lifts the "preview" of the Windows files (spec 0043 S8).
After that, run it again before a release that touches PC/SC or Windows
code.

## What you need

- A Windows 11 (or 10 22H2) x86-64 machine with a USB port: a PC, or a VM
  with the YubiKey passed through (spec 0041 Q6).
- An expendable YubiKey: `yb format` and the PIN tests change it.
- A second YubiKey, if available, for the device picker.
- The release's `yb-X.Y.Z-windows-x86_64.zip` and
  `libyubiblob-A.B.C-windows-x86_64.zip`, or the artifact `windows` of a
  dry run of the Publish workflow.  Nothing is built on the machine,
  except the C test.
- For the C test: Visual Studio Build Tools (MSVC), and
  `rust/yubiblob/tests/c/smoke.c` from the repository.
- A Linux machine with yb, for the cross-system checks.

## Checklist

In PowerShell, with `yb.exe` on the `PATH`.  Write down anything
unexpected, even when the step passes.

### The download

1. `Get-FileHash` of each zip matches `SHA256SUMS`.
2. `gh attestation verify <zip> --repo douzebis/yb` succeeds (if `gh` is
   installed).
3. `yb --version` prints the release's version; no missing-DLL error.

### Finding the YubiKey

4. `yb list-readers` shows the YubiKey's reader.
5. With two YubiKeys: `yb ls` asks which one (picker by serial);
   `yb --serial N ls` picks it without asking.
6. Unplug and replug the YubiKey; `yb ls` still finds it.

### Format

7. `yb format`, guided: it goes straight to a legacy store (no
   "post-quantum" question); follow it to the end.
8. `yb format` with flags, as in the README's Quick Start.
9. `yb fsck` reports a healthy store.

### Blobs

10. `yb store` a text file and a binary file (e.g. a `.zip`); `yb ls`,
    `yb ls -l` list them.
11. `yb fetch -o out.bin`: the file is identical
    (`Get-FileHash` on both).
12. `yb fetch` to standard output, redirected to a file with
    `cmd /c "yb fetch -p name > out.bin"`: identical too.  Note what
    PowerShell's own `>` does (it may re-encode text: document it if so).
13. A blob name with non-ASCII characters (e.g. `été.txt`): stored,
    listed and fetched; `yb ls` shows the name correctly.
14. `yb rm` a blob; `yb ls` no longer lists it.

### Errors

15. A wrong PIN: refused, with the attempts left; the right PIN then
    works.
16. Pull the YubiKey out during a `yb store` of a large file; plug it
    back: `yb fsck` reports the store intact, and the blob has its old
    content or the new one (invariant 0001).
17. A post-quantum store, made on Linux: every command says
    "post-quantum stores are not supported on Windows", and changes
    nothing.

### Across systems

18. A legacy store made on Windows: listed, fetched and checked on Linux.
19. A legacy store made on Linux: listed, fetched and checked on Windows.

### libyubiblob

20. Unpack the libyubiblob zip; build the C test with MSVC (in a
    "Developer Command Prompt"):

    ```
    cl /W4 /WX smoke.c /I include lib\yubiblob.dll.lib
    ```

    then run `smoke.exe <PIN>` with `bin\yubiblob.dll` next to it, on a
    YubiKey set up by `yb format --protect`: it prints
    `libyubiblob from C: ok`.

## Record of passes

| Date | yb | Windows | YubiKey firmware | Result | By |
|---|---|---|---|---|---|
| | | | | | |
