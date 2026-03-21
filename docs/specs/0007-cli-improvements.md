<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0007 — CLI Improvements

**Status:** draft
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

The `yb` CLI has a number of usability and correctness issues discovered
during design review:

1. `--pin` and `--key` appear on the command line, exposing secrets in
   shell history and `ps` output.  Comparable CLIs handle this as follows:
   - **gpg**: no passphrase flag; delegates to `gpg-agent` + pinentry
     (always prompts on `/dev/tty`).
   - **ssh-add**: no flag; prompts interactively or uses `SSH_ASKPASS`.
   - **age**: `--passphrase` triggers an interactive prompt only; env vars
     intentionally unsupported.
   - **openssl**: `-passin env:VAR` / `-passin file:PATH` / `-passin fd:N`
     / `-passin stdin`; direct `pass:VALUE` is explicitly documented as
     insecure.
   - **ykman** (YubiKey Manager): accepts `--pin` as a flag, same as our
     current code — this is the known-bad pattern.
   - **vault**: omitting the password flag triggers an interactive prompt;
     passing it inline is documented as insecure.
   - **docker login**: `--password-stdin` reads from stdin; bare `--password`
     flag exists but is warned against.
   - **aws CLI**: `AWS_SECRET_ACCESS_KEY` env var; no inline flag.
   The consensus pattern is: **interactive TTY prompt by default**
   (always on `/dev/tty`, regardless of stdin redirection);
   **environment variable** as the non-interactive escape hatch;
   **stdin** (`--pin-stdin`) as the pipe-friendly alternative.
   Direct CLI flags for secrets are universally considered insecure.
2. `store [NAME] -i FILE` puts the source file behind a flag and
   puts the destination name first, contrary to the Unix convention of
   source-before-destination (`cp src dst`).  Multiple files cannot be
   stored in one invocation.
3. `fetch` has no way to retrieve blobs by pattern; fetching everything
   requires multiple invocations; the `--extract` flag name is borrowed
   from tar with no obvious meaning here.
4. `list` output has no column headers, uses an ambiguous encryption flag
   character (`-` for encrypted, `U` for unencrypted), and always shows
   the chunk count which is not meaningful to most users.
5. `--key-slot` on `format` accepts a bare hex string (`82`) whose
   relationship to a decimal number is silently ambiguous.
6. `fsck` always dumps the full raw object table even for a healthy store,
   making it noisy in scripted use.
7. `list-readers` calls `Context::new`, which fails with "no YubiKey
   found" — the one situation where `list-readers` is most needed.
8. No `--quiet` flag; informational stderr output cannot be suppressed for
   scripts.
9. `remove` accepts only one blob name per invocation.

Out of scope for this spec: `rotate-key` (tracked separately).

## Goals

1. PIN and management key are never required on the command line.
2. `store FILE…` copies files into the store by basename; `--name` overrides the blob name; stdin requires `--name`.
3. `fetch PATTERN…` saves to files by default; `--stdout` / `-p` pipes to stdout (single match only); `--output-dir` / `-O` sets destination directory.
4. `list` mirrors `ls`: default is names only; `-l` adds flag, chunks,
   date, size; `-t`/`-r`/`-1` control sort order and format.
5. `--key-slot` on `format` accepts both decimal and `0x`-prefixed hex.
6. `fsck` defaults to a one-line summary; `--verbose` gives the full dump.
7. `list-readers` works even when no YubiKey is connected.
8. Global `--quiet` / `-q` suppresses informational stderr output.
9. `remove` accepts one or more blob names or glob patterns.
10. Shell completion scripts for bash, zsh, and fish are generated at
    Nix build time via a hidden `completions` subcommand.

## Non-goals

- `rotate-key` command (tracked separately).
- Changing the binary store format.
- Changing the encryption scheme.
- Interactive PIN retry loop (one attempt per invocation is sufficient).

## Specification

**Backward compatibility policy:** `yb` is published on GitHub and in
nixpkgs.  Where feasible, old flags are retained as hidden options
(`#[arg(hide = true)]`) that emit a deprecation warning to stderr but
still work.  Sections below mark each changed flag as either:
- **[compat: hidden deprecated alias retained]** — old flag still
  accepted, deprecated warning emitted, behavior unchanged.
- **[compat: BREAKING]** — old behavior cannot be preserved; callers
  must update.  Breaking changes are minimized.

### Current syntax reference

```
# Global flags (all commands)
yb [-s SERIAL] [-r READER] [-k KEY] [--pin PIN] [--debug] [--allow-defaults]

# format   (-s on format means --object-size, not --serial)
yb format [-c COUNT] [-s SIZE] [-k SLOT] [-g] [-n SUBJECT]

# store
yb store [NAME] [-i FILE] [-e | -u]

# fetch
yb fetch NAME… [-o FILE] [-x]

# list  (alias: ls)
yb list [PATTERN]

# remove  (alias: rm)
yb remove NAME

# fsck
yb fsck

# list-readers
yb list-readers
```

After this spec the new signatures will be:

```
# Global flags
yb [-s|--serial SERIAL] [-r|--reader READER] [-q|--quiet]
   [--pin-stdin] [--debug] [--allow-defaults]
   (--pin and --key hidden/deprecated; use YB_PIN / YB_MANAGEMENT_KEY)

# format
yb format [-c|--object-count COUNT] [-s|--object-size SIZE]
          [-k|--key-slot SLOT] [-g|--generate] [-n|--subject SUBJECT]
   # -g / --generate: generate a new EC P-256 key pair in SLOT and
   #   write a self-signed certificate; without -g the slot must
   #   already contain a certificate.

# store
yb store FILE… [-n|--name NAME] [-e|--encrypted | -u|--unencrypted]
yb store --name NAME [-e|-u]          # read payload from stdin

# fetch
yb fetch PATTERN… [-p|--stdout] [-o|--output FILE] [-O|--output-dir DIR]

# list  (alias: ls)
yb list [-l|--long] [-1] [-r|--reverse] [-t|--sort-time] [PATTERN]

# remove  (alias: rm)
yb remove [-f|--ignore-missing] PATTERN…

# fsck
yb fsck [-v|--verbose]

# list-readers
yb list-readers

# completions  (no subcommand; activated via env var)
YB_COMPLETE=bash yb    # prints bash completion script and exits
YB_COMPLETE=zsh  yb    # same for zsh
YB_COMPLETE=fish yb    # same for fish
```

### S1 — PIN and management key from environment / prompt

**`--pin` removal:**

- Remove `--pin` as a documented global flag.
- PIN resolution order (first match wins):
  1. `--pin-stdin` flag (explicit invocation-time intent overrides
     ambient environment): read one line from stdin, trimming newline.
     Useful in pipes: `echo "123456" | yb --pin-stdin fetch secret`.
  2. Environment variable `YB_PIN` (if set and non-empty).
  3. Prompt `Enter YubiKey PIN: ` with echo disabled on `/dev/tty`
     directly (use `rpassword::prompt_password` which opens `/dev/tty`
     unconditionally, not stdin — consistent with `gpg` and `docker`).
  4. `None` — operations that require a PIN fail with:
     `PIN required; set YB_PIN, use --pin-stdin, or run interactively`.
- Keep `--pin` as a hidden (`#[arg(hide = true)]`) flag for backward
  compatibility; emit a deprecation warning to stderr when it is used:
  `Warning: --pin is deprecated; use YB_PIN, --pin-stdin, or interactive prompt`.
  **[compat: hidden deprecated alias retained]**

**`--key` removal:**

- Apply the same pattern to `--key` (management key):
  1. `YB_MANAGEMENT_KEY` environment variable.
  2. No `--key-stdin` and no TTY prompt (48 hex chars; not practical
     interactively; PIN-protected mode covers the common case).
  3. `None` — PIN-protected mode or allow-default path.
- Keep `--key` as a hidden flag with the same deprecation warning:
  `Warning: --key is deprecated; use YB_MANAGEMENT_KEY`.
  **[compat: hidden deprecated alias retained]**

**No other changes** to how the resolved PIN / management key is used
internally.

### S2 — `store` argument redesign

Current signature: `yb store [NAME] [-i FILE] [-e|-u]`

New signature:
```
yb store FILE… [-n NAME] [-e|-u]
yb store -n NAME    [-e|-u]    # read from stdin
```

**Note — in-place store:** The Python design doc mentions a planned
`--in-place` / `-i` flag that would reuse the existing object slots
rather than allocating new ones, avoiding a double-write.  It is
documented there as unsafe if the YubiKey is physically removed mid-write
(the old data is gone, the new data is incomplete).  The Python version
never implemented it; the Rust version does not implement it either.
Not in scope for this spec.

The yb blob store is a flat namespace (no paths, just names).  The
natural model is "copy files into the store", mirroring `cp`:

- `FILE…` — one or more source files (paths).  The blob name for each
  is its basename (e.g., `secrets/id_ed25519` → blob name `id_ed25519`).
  Shell glob expansion is handled by the shell before `yb` sees the
  arguments, so `yb store keys/*` already works without any special
  handling in the program.
  - **Basename collision**: if two or more `FILE` arguments expand to the
    same basename (e.g., `dir1/config` and `dir2/config`), `yb` errors
    before writing anything: `error: duplicate blob name 'config' from
    'dir1/config' and 'dir2/config'`.  Use `-n` to resolve.
- `-n NAME` / `--name NAME` — override the blob name.  Only valid when
  exactly one `FILE` is given, or when reading from stdin.
- Stdin: if no `FILE` arguments are given, payload is read from stdin;
  `-n NAME` is then required.

Resolution rules:

| `FILE…` | `-n NAME` | Payload | Blob name |
|---|---|---|---|
| one file | absent | file contents | basename of FILE |
| one file | present | file contents | NAME |
| multiple files | absent | each file | each basename |
| multiple files | present | error | — |
| none | present | stdin | NAME |
| none | absent | error | — |

**Store-full behavior:**

`store_blob` in the orchestrator checks `store.free_count() >= chunks_needed`
before allocating any objects and returns `Ok(false)` if the store cannot
fit the blob.  For a single file this maps to:

```
error: store is full — remove some blobs first (need N slots, 0 free)
```

For multiple files (`yb store FILE…`), the check must cover all files
before writing any of them:

1. Read store, sanitize.
2. For each file, compute `chunks_needed` (based on encrypted payload
   size and the name's contribution to head capacity).
3. Sum all `chunks_needed`.  If the total exceeds `store.free_count()`,
   error before writing anything:
   ```
   error: store is full — need N slots for 3 files, only M free
   ```
4. Only if all files fit: allocate and write, then call `store.sync()`
   once.

This all-or-nothing guarantee means the store is either fully updated
or entirely unchanged; no partial multi-file store is ever written.

**Backward compatibility:** The old `yb store NAME -i FILE` syntax
(`NAME` first, file as a `-i` flag) cannot be retained as a hidden
alias because clap does not support two positional interpretations of
the same argument list.  **[compat: BREAKING]** — users must change
`yb store NAME -i FILE` to `yb store FILE -n NAME`.

### S3 — `fetch`: glob patterns, save-to-file default, `--stdout`

New signature:
```
yb fetch PATTERN… [-p|--stdout] [-o|--output FILE] [-O|--output-dir DIR]
```

- `PATTERN…` — one or more blob names or glob patterns (e.g., `*`,
  `secret-*`, `config`).  A plain name with no wildcard characters is
  an exact match.  Passing `*` fetches every blob.  Glob syntax follows
  `globset` (same library already used by `list`).
- **Default behavior** (no output flag): write each blob to a file
  named after the blob in the current directory (or `--output-dir`).
  This mirrors `store`: what you put in comes back out as files.
- `-p` / `--stdout` — write blob content to stdout.  (`-p` for "print",
  the same mnemonic used by `pass show -p` and `gpg --decrypt`; `-o -`
  would conflict with `-o FILE`.)  Only valid when the pattern matches
  **exactly one blob**; errors otherwise.  Useful for piping:
  `yb fetch config --stdout | grep api_key`.
- `-o FILE` / `--output FILE` — write to `FILE`.  Only valid when
  exactly one blob matches.  Mutually exclusive with `-p`.
- `-O DIR` / `--output-dir DIR` — write files into `DIR` instead of
  the current directory (default: `.`).  Cannot be combined with `-p`
  or `-o`.
- `--extract` / `-x`: the default now saves to files, so `--extract`
  is superseded.  Keep `-x` / `--extract` as a hidden no-op alias that
  emits a deprecation warning: `Warning: --extract is deprecated; saving
  to files is now the default behavior`.
  **[compat: hidden deprecated alias retained]**

**Default behavior change:** Previously `yb fetch NAME` without flags
wrote to stdout.  Now it writes to a file named `NAME` in the current
directory.  Callers that relied on stdout must add `-p`.
**[compat: BREAKING]**

Behavior matrix:

  | Pattern result | no flag | `-p` | `-o FILE` | `-O DIR` |
  |---|---|---|---|---|
  | exactly one blob | write to file | stdout | write to FILE | write to DIR/name |
  | multiple blobs | write each to file | error | error | write each to DIR/name |
  | no match | error | error | error | error |

If a pattern contains glob metacharacters (`*`, `?`, `[`) and matches
nothing, that is an error.  A plain name that matches nothing is also
an error (consistent with current behavior).

### S4 — `list` output formatting

Mirrors `ls` flag semantics.

**Default (no flags):** names only, one per line — like `ls` without flags:

```
config
my-secret
```

**`-l` / `--long`:** full metadata, like `ls -l` — no header row, fixed
columns, flag character, chunk count, date, size, name:

```
-  1 Mar  5 14:33   256 my-secret
-  1 Mar  5 14:32    42 config
P  2 Mar  4 09:11  1024 backup
```

Column layout (left to right):

- **Flag** (1 char): `-` = encrypted, `P` = plaintext (unencrypted).
  Encryption is the normal case so `-` is unobtrusive; `P` stands out
  as the exception.
- **Chunks** (right-aligned, 2 chars): number of PIV objects consumed.
  Chunks matter because the YubiKey store has a fixed slot budget; a
  2-chunk blob consumes twice the space.
- **Date** (12 chars): `%b %e %H:%M` for entries ≤ 180 days old;
  `%b %e  %Y` for older entries — identical to `ls -l` convention.
- **Size** (right-aligned, 6 chars): plaintext size in bytes.
- **Name**: blob name.

**`-1`**: one name per line (explicit; same as the default, but useful
when piping and the terminal might otherwise trigger multi-column output
in a future version).

Additional sort/order flags (combinable, same semantics as `ls`):

- `-t` / `--sort-time`: sort by modification time, newest first
  (default sort is by name ascending).
- `-r` / `--reverse`: reverse the current sort order.

The `PATTERN` positional argument is unchanged (glob filter).

### S5 — `--key-slot` hex/decimal

On `format`, `--key-slot` currently silently strips a leading `0x` and
parses the remainder as hex, so `82` is interpreted as hex `0x82 = 130`.

New behavior:

- If the value starts with `0x` or `0X`: parse the remainder as
  hexadecimal.
- Otherwise: parse as decimal.
- Either way, if the result is not in `0x80..=0x95` (the retired key
  slots) or the standard slots `0x9A`, `0x9C`, `0x9D`, `0x9E`, emit a
  warning: `Warning: slot 0xNN is not a standard PIV key slot`.
- The confirmation message already shows `0xNN`; keep it.
- Default value changes from `"82"` (ambiguous) to `"0x82"` (explicit
  hex).

### S6 — `fsck` verbosity

Default output (no flags):

```
Store: 12 objects × 3052 bytes, slot 0x82, age 5
Blobs: 3 stored, 9 free
Status: OK
```

If anomalies are detected (orphaned chunks, duplicate names):

```
Store: 12 objects × 3052 bytes, slot 0x82, age 5
Blobs: 3 stored, 9 free
Status: 1 warning(s)
  WARNING: object 7 is an orphaned continuation chunk (no reachable head)
```

Exit code 1 when any warning is reported.

`--verbose` / `-v` prints the full per-object dump (current default
behavior), followed by the summary and status lines.

`fsck` does **not** auto-sanitize; it only reports. The user runs
`store`/`remove` to fix issues.

### S7 — `list-readers` bypasses Context

`list-readers` must not call `Context::new`.  Instead:

- In `run()`, match `Commands::ListReaders` **before** constructing the
  `Context` and dispatch directly to a function that calls
  `HardwarePiv::new().list_readers()`.
- The global `--serial`, `--reader`, `--key`, `--pin`, `--debug`,
  `--allow-defaults` flags are irrelevant for `list-readers`; they are
  parsed but silently ignored.

### S8 — Global `--quiet` / `-q` and progress feedback

Add `--quiet` / `-q` to the top-level `Cli` struct.

**Progress bar** (replaces dot-per-object output):

YubiKey writes are slow (~300 ms per object).  The current dot-per-object
output (`....`) reassures the user that the operation has not hung, but
it cannot be suppressed and gives no indication of how many writes remain.
Replacement: a single updating progress line on stderr, implemented with
the `indicatif` crate:

```
Writing objects: [=====>    ] 5/12
```

- Rendered using `\r` in-place; a final `\n` is printed on completion.
- Applied to **both** `Store::sync` (used by `store`, `remove`, `fsck`)
  and `Store::format` (used by `format`).
- **Auto-suppressed** when stderr is not a TTY (CI, pipes) — falls back
  to no output.
- **Suppressed** when `--quiet` is set.
- No need to thread a `quiet` flag into `Store::sync`; TTY detection at
  the `indicatif` call site is sufficient.

**`--quiet` behavior:**

- Suppress all informational stderr output: progress bar, "Stored 'X'",
  "Removed 'X'", "Extracted 'X'", `fsck` summary lines.
- The top-level `Error: …` line in `main` is **not** suppressed.
- `--quiet` is stored in `Context` (`pub quiet: bool`) and checked at
  each informational output site.

### S9 — `remove` multiple names and glob patterns

New signature: `yb remove [-f|--ignore-missing] PATTERN…`

- `PATTERN…` — one or more blob names or glob patterns, same syntax as
  `fetch` and `list`.  A plain name is an exact match; `*` removes
  everything.
- If a glob pattern matches nothing, that is an error unless `-f` is set.
- If a plain name matches nothing, that is always an error (a typo is
  more likely than an intentional no-op).
- `-f` / `--ignore-missing`: silently skip patterns that match nothing;
  exit 0 even if nothing was removed.
- Matching is done before any removal begins.  If two patterns overlap
  (both match the same blob), the blob is removed once.
- A single `Store::sync` call after all removals, to minimize writes.

### S10 — Shell completion scripts

**Approach:** `CompleteEnv` + `ArgValueCompleter` from `clap_complete`'s
`engine` module, following the same pattern as `prototools/prototext`.
This provides both static flag completion and dynamic value completion
(blob names, file paths, directory paths, serial numbers) in a single
mechanism.  No separate `completions` subcommand is needed.

**Activation (cargo-style, via environment variable):**

```bash
# Bash
source <(YB_COMPLETE=bash yb)

# Zsh
source <(YB_COMPLETE=zsh yb)

# Fish
YB_COMPLETE=fish yb | source
```

When `YB_COMPLETE=<shell>` is set, `yb` detects this at startup via
`CompleteEnv`, prints the completion script to stdout, and exits — no
YubiKey access occurs.

**Cargo dependencies:**
```toml
[dependencies]
clap_complete = { version = "4", features = ["unstable-dynamic"] }
```

**Implementation sketch:**

```rust
// main.rs — before Cli::parse()
CompleteEnv::with_factory(Cli::command)
    .var("YB_COMPLETE")
    .complete();

let cli = Cli::parse();
```

Dynamic completers are attached to individual arguments via
`add = ArgValueCompleter::new(complete_fn)` in the clap derive macros.
A `complete.rs` module (following `prototools/prototext/src/complete.rs`)
provides the completer functions.

**What completions cover:**

| Argument | Completer | How |
|---|---|---|
| `-s`/`--serial` | serial numbers | `HardwarePiv::new().list_devices()` → serials |
| `store FILE…` | file paths | filesystem (cwd-relative, all files) |
| `fetch PATTERN…` | blob names | YubiKey blob list (see below) |
| `list PATTERN` | blob names | YubiKey blob list |
| `remove PATTERN…` | blob names | YubiKey blob list |
| `-O`/`--output-dir` | directory paths | filesystem (dirs only) |
| `-o`/`--output` | file paths | filesystem (all files) |
| Subcommand names | static | clap_complete built-in |
| All flags | static | clap_complete built-in |

**Blob name completion** (`complete_blob_names`):

```rust
pub fn complete_blob_names(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    // Connect silently; return empty on any error.
    let piv = HardwarePiv::new();
    let Ok(devices) = piv.list_devices() else { return vec![]; };
    let Some(device) = devices.into_iter().next() else { return vec![]; };
    let Ok(store) = Store::from_device(&device.reader, &piv) else { return vec![]; };
    let prefix = incomplete.to_string_lossy();
    orchestrator::list_blobs(&store)
        .into_iter()
        .filter(|b| b.name.starts_with(prefix.as_ref()))
        .map(|b| CompletionCandidate::new(b.name))
        .collect()
}
```

If multiple YubiKeys are connected, completion uses the first one found
(same as the default device selection when `--serial` is not given).
All errors during completion are silently swallowed — a failed
completion is better than an error message interrupting the shell.

**Serial number completion** (`complete_serials`):

```rust
pub fn complete_serials(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let piv = HardwarePiv::new();
    let Ok(devices) = piv.list_devices() else { return vec![]; };
    let prefix = incomplete.to_string_lossy();
    devices.into_iter()
        .map(|d| d.serial.to_string())
        .filter(|s| s.starts_with(prefix.as_ref()))
        .map(CompletionCandidate::new)
        .collect()
}
```

**How the generated script works:**

When `YB_COMPLETE=bash yb` runs, `clap_complete` emits a bash function
that, at tab-completion time, re-invokes the binary with
`YB_COMPLETE=bash` and the partial command line appended after `--`.
The binary path is embedded **verbatim as `argv[0]`** from the process
that generated the script.  Consequently:

- Built from the Nix package (`$out/bin/yb`): embeds the Nix store path
  `/nix/store/…-yb/bin/yb` — stable, correct for all users.
- Built locally (`target/release/yb`): embeds the absolute dev-checkout
  path — correct for that developer's machine only.
- Installed via `cargo install` (`~/.cargo/bin/yb`): embeds that path —
  correct for that user.

**Known bash bug in `clap_complete` — sed workaround required:**

`clap_complete` 4.5.x has two bugs in its bash generator that affect
any completer returning filesystem paths (`FILE…`, `-O DIR`, `-o FILE`):

1. `words[COMP_CWORD]="$2"` — bash's `$2` is the word at the cursor as
   bash tokenises it.  When the cursor is mid-word (e.g. `dir/par<Tab>`)
   bash splits on `/`, so `$2` = `par` instead of `dir/par`.  Fix:
   read from `${COMP_LINE:0:${COMP_POINT}}` directly.

2. Missing `compopt -o filenames` — without this bash does not apply
   filename quoting/escaping to results, so paths with spaces or special
   characters break.

These bugs do not affect zsh or fish.  The workaround is to pipe the
generated bash script through `sed` before sourcing or installing it:

```bash
YB_COMPLETE=bash yb | sed \
  -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
  -e 's|words\[COMP_CWORD\]="$2"|local _cur="${COMP_LINE:0:${COMP_POINT}}"; _cur="${_cur##* }"; words[COMP_CWORD]="${_cur}"|'
```

**Nix package install** (`nix profile install`, nixpkgs, NixOS):

Add to `ybRust` in `default.nix`.  The `postInstall` hook runs at build
time with the binary at `$out/bin/yb`, so the baked-in path is the final
store path.  No YubiKey is needed — `YB_COMPLETE` makes the binary print
a script and exit immediately.

```nix
ybRust = crane.buildPackage (rustCommon // {
  ...
  nativeBuildInputs = rustCommon.nativeBuildInputs ++ [ pkgs.installShellFiles ];

  postInstall = ''
    installShellCompletion --cmd yb \
      --bash <(YB_COMPLETE=bash $out/bin/yb | sed \
        -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
        -e 's|words\[COMP_CWORD\]="$$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
      --zsh  <(YB_COMPLETE=zsh  $out/bin/yb) \
      --fish <(YB_COMPLETE=fish $out/bin/yb)
  '';
  ...
});
```

(In Nix strings: `''${...}` escapes a literal `${`; `$$` escapes a
literal `$`.)

`installShellCompletion` writes files to:
- `$out/share/bash-completion/completions/yb`
- `$out/share/zsh/site-functions/_yb`
- `$out/share/fish/vendor_completions.d/yb.fish`

NixOS and Home Manager pick these up automatically; users need do
nothing after installation.

**Nix dev shell** (`nix-shell`):

Add to the dev-shell `shellHook` in `default.nix`.  Completions are
active for the duration of the shell session and regenerated on each
entry (so they always reflect the currently built binary):

```nix
shellHook = ''
  ...
  if command -v yb &>/dev/null; then
    source <(YB_COMPLETE=bash yb | sed \
      -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
      -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|')
  fi
'';
```

The `if command -v yb` guard makes shell startup non-fatal if the
binary has not been built yet.

**`cargo install`:**

`cargo install` copies only the binary; no post-install hooks exist in
Cargo.  Users must add completions manually.  Document in the README:

```bash
# Bash — add to ~/.bashrc
source <(YB_COMPLETE=bash yb | sed \
  -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
  -e 's|words\[COMP_CWORD\]="$2"|local _cur="${COMP_LINE:0:${COMP_POINT}}"; _cur="${_cur##* }"; words[COMP_CWORD]="${_cur}"|')

# Zsh — add to ~/.zshrc
source <(YB_COMPLETE=zsh yb)

# Fish — run once
YB_COMPLETE=fish yb > ~/.config/fish/completions/yb.fish
```

**Backward compatibility:** no existing flags or subcommands changed.

## Open questions

None.

## References

- `rust/yb/src/main.rs` — current top-level CLI
- `rust/yb/src/cli/` — current command implementations
- `docs/specs/0006-security-hardening.md` — PIN-on-command-line risk (sec finding 6.1/6.2 context)
- `rust/docs/DESIGN.md` — CLI command reference
