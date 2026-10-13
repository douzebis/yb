<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0036 — Bash Completion from the Raw Command Line

**Status:** in-progress
**App:** yb
**Implemented in:** <!-- YYYY-MM-DD, fill after implementation -->

## Problem

yb's completions come from clap_complete's dynamic engine (`CompleteEnv`).
Its bash script hands the binary `COMP_WORDS`, which bash has already
split at `COMP_WORDBREAKS` (`=`, `:` and others), and installs no `-o
filenames`.  Spec 0020 found both problems and kept two `sed` patches
(in `nixpkgs/…/package.nix` and in the dev shell), pending upstream
fixes (clap PR #6364, still open).

prototools measured the same patches by pressing Tab in an interactive
bash (its spec 0406, 2026-10-10): the second patch, which rebuilds the
current word from `COMP_LINE`, **corrupts the command line** after a `=`
or `:` (e.g. `--opt=value`, paths containing `:`) and breaks the quoted
words it was meant for.  yb ships the same patches.

prototools replaced them with a completer that receives the raw command
line, splits it as the shell would, asks clap's engine for whole words,
and keeps of each candidate only the part readline replaces, using only
clap_complete's public API: crate `prototools-complete` (spec 0406).

## Goals

- **G1 — Correct bash completion** for subcommands, options, values,
  blob names (dynamic), serial numbers and paths, including words with
  `=`, `:`, spaces or quotes; a completion never corrupts the line.
- **G2 — No patching.**  The script `YB_COMPLETE=bash yb` prints is the
  script installed, by the dev shell and by the nixpkgs recipe: the `sed`
  patches go.
- **G3 — A crate of its own,** `clap-complete-rawline`, in yb's
  workspace, derived from `prototools-complete` (same author, MIT), with
  nothing yb-specific in it, so that it can later become a standalone
  project (and nixpkgs package) that yb and prototools both depend on.

## Non-goals

- zsh, fish, elvish, PowerShell: clap_complete's scripts, unchanged.
- Making the crate standalone now (later; see G3).
- Shell syntax beyond words, quotes and backslashes in the line being
  completed (`$'…'`, variables, globs…): bash's default completion takes
  over (`-o bashdefault`).

## Specification

- **Crate** `rust/clap-complete-rawline`: the code of
  `prototools-complete` 0.3.3, renamed (crate, bash function names), its
  version independent of yb's (starting at 0.1.0), license MIT.  Public
  API: `shells()`, for `CompleteEnv::shells`, and `complete_line()`.
- **yb** (`main.rs`): `CompleteEnv::with_factory(…).var("YB_COMPLETE")
  .shells(clap_complete_rawline::shells())`.
- **Dev shell** (`default.nix`): the `sed` on the completion script goes.
- **nixpkgs recipe** (`nixpkgs/…/package.nix`): the two
  `substituteInPlace` patches go, completion installed as printed.  Staged
  here; reaches nixpkgs with the next yb release (a follow-up PR).
- **crates.io:** yb depends on the crate, so it is published with yb
  (added to `scripts/check-crates`, `scripts/publish-crates`, and the
  publish workflow, before `yb`).  crates.io allows a trusted publisher
  only for a crate that exists: its first upload is done once by the
  maintainer with a personal token, then a trusted publisher is added as
  for `yb` and `yb-core`.
- **Tests:** the crate's unit tests (line splitting, trimming), and yb
  tests completing through `complete_line` with yb's command: subcommands,
  `--serial=`, a path with a space, a path with `:`, a blob name, a quoted
  blob name.

## Open questions

None.

## References

- Spec 0020 — the `sed` patches (superseded by this spec).
- prototools spec 0406 and crate `prototools-complete` 0.3.3.
- clap-rs/clap#6280, #6364.
