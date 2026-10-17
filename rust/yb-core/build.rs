// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Link libfido2 (spec 0028, D9), found with pkg-config.

fn main() {
    // Not on Windows (see `fido2` in lib.rs).
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        return;
    }
    if let Err(e) = pkg_config::Config::new()
        .atleast_version("1.10")
        .probe("libfido2")
    {
        panic!(
            "libfido2 (1.10 or later) was not found: install its development \
             files (Debian/Ubuntu: libfido2-dev; Fedora: libfido2-devel; \
             Homebrew: libfido2) and pkg-config.\n{e}"
        );
    }
}
