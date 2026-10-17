// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

// Link libfido2, found with pkg-config (e.g. inside
// `nix-shell -p libfido2 pkg-config`), and record its directory as rpath.
use std::process::Command;

fn main() {
    let out = Command::new("pkg-config")
        .args(["--variable=libdir", "libfido2"])
        .output()
        .expect("pkg-config not found");
    assert!(out.status.success(), "pkg-config cannot find libfido2");
    let lib = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    println!("cargo:rustc-link-search=native={lib}");
    println!("cargo:rustc-link-lib=dylib=fido2");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{lib}");
}
