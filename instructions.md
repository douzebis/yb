# SPDX and REUSE Compliance

All projects use the [REUSE spec](https://reuse.software/) for license
compliance.  Use the `reuse` CLI (available in the project's nix-shell).

## Checking compliance

```bash
reuse lint          # must pass 100% before any commit that touches headers
```
## Adding or updating copyright headers

Always use `reuse annotate` — never edit SPDX headers by hand.

```bash
# New file (source):
reuse annotate --copyright "Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)" --license MIT --fallback-dot-license path/to/file
```
For files imported from other projects, add and `[[annotations]]` block to REUSE.toml instead.

## Workflow summary

1. Edit/create files.
2. `reuse annotate` any new files (or files gaining a new copyright holder).
3. `reuse lint` — must be clean before committing.