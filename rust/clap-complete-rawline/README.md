<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# clap-complete-rawline

Bash completion for [clap](https://crates.io/crates/clap) programs, from
the raw command line.

clap_complete's dynamic bash script hands the program `COMP_WORDS`, which
bash has already split at `COMP_WORDBREAKS` (`=`, `:` and others), so
`--opt=value` or a path containing `:` completes wrongly or not at all.
This crate's script passes the raw line up to the cursor instead; the
crate splits it as the shell would, asks clap_complete's engine for whole
words, and keeps of each candidate only the part readline replaces.  It
uses only clap_complete's public API, and replaces bash only: the other
shells are clap_complete's.

```rust
use clap::CommandFactory;
use clap_complete::CompleteEnv;

CompleteEnv::with_factory(Cli::command)
    .var("MYTOOL_COMPLETE")
    .shells(clap_complete_rawline::shells())
    .complete();
```

Then `source <(MYTOOL_COMPLETE=bash mytool)`.

Derived from `prototools-complete` (spec 0406 of
[prototools](https://github.com/douzebis)); see yb's spec 0036.
