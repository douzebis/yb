// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `yb-gen-man` — generate man pages from the live clap definition.
//!
//! Usage (from workspace root):
//!   cargo run -p yb --bin yb-gen-man [-- <output-dir>]
//!
//! Generates:
//!   <output-dir>/yb.1
//!   <output-dir>/yb-format.1
//!   <output-dir>/yb-store.1
//!   <output-dir>/yb-fetch.1
//!   <output-dir>/yb-list.1
//!   <output-dir>/yb-remove.1
//!   <output-dir>/yb-fsck.1
//!   <output-dir>/yb-list-readers.1
//!   <output-dir>/yb-select.1

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "man/man1".to_owned()),
    );

    std::fs::create_dir_all(&out_dir).expect("cannot create output directory");

    let cmd = yb::command();

    // Top-level page.
    write_man(&out_dir, &cmd, "yb");

    // One page per subcommand (skip "help" which is auto-injected by clap).
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        if name == "help" {
            continue;
        }
        let page_name = format!("yb-{name}");
        write_man(&out_dir, sub, &page_name);
    }
}

/// Extra roff sections appended after the clap-generated content.
/// Returns `(description_override, extra_roff)` where `description_override`
/// replaces the one-liner DESCRIPTION when non-empty.
fn extra_sections(page: &str) -> (&'static str, &'static str) {
    match page {
        "yb" => (
            r#".PP
\fByb\fR stores and retrieves arbitrary binary blobs on a YubiKey's PIV
applet.  Each blob is encrypted with a per-device ECDH key before being
written to the on-card PIV data objects; without the YubiKey the data
cannot be decrypted.
.PP
The store is a flat sequence of fixed-size PIV objects provisioned by
\fByb format\fR.  Large blobs are automatically split across multiple
objects (chunk chaining); the number of objects and object size can be
tuned at format time to trade capacity for per-object write speed.
.PP
All write operations (\fBformat\fR, \fBstore\fR, \fBremove\fR) require both the
PIV PIN and the PIV management key.  Read operations (\fBfetch\fR,
\fBlist\fR, \fBfsck\fR) that decrypt data require the PIN; purely
structural reads do not."#,
            r#".SH ENVIRONMENT
.TP
\fBYB_PIN\fR
PIV PIN.  Takes precedence over the interactive prompt.
Superseded by \fB\-\-pin\-stdin\fR when both are set.
.TP
\fBYB_MANAGEMENT_KEY\fR
PIV management key as a hex string.  Required for write operations when
the factory default has been changed (recommended).
.TP
\fBYB_COMPLETE\fR
Shell name (\fBbash\fR, \fBzsh\fR, \fBfish\fR).  When set, \fByb\fR emits shell
completion code to stdout and exits.
.SH EXAMPLES
.PP
Provision a new store (20 objects, default size) and generate an ECDH key:
.RS
.nf
yb format \-\-generate
.fi
.RE
.PP
Store an encrypted file:
.RS
.nf
yb store secret.key
.fi
.RE
.PP
Retrieve it to the current directory:
.RS
.nf
yb fetch secret.key
.fi
.RE
.PP
List all blobs with details:
.RS
.nf
yb list \-\-long
.fi
.RE
.SH SECURITY
Blobs are encrypted with AES-256-GCM using a key derived via ECDH with a
P-256 private key that never leaves the YubiKey hardware.
.PP
\fBDo not\fR use the factory-default PIN or management key in production.
\fByb\fR refuses to operate with default credentials unless
\fB\-\-allow\-defaults\fR is passed.
.SH SEE ALSO
\fByb\-format\fR(1),
\fByb\-store\fR(1),
\fByb\-fetch\fR(1),
\fByb\-list\fR(1),
\fByb\-remove\fR(1),
\fByb\-fsck\fR(1),
\fByb\-list\-readers\fR(1),
\fByb\-select\fR(1),
\fBykman\fR(1)"#,
        ),

        "yb-format" => (
            r#".PP
Prepare a YubiKey for use with \fByb\fR(1).
\fBformat\fR writes a fresh store header and allocates \fICOUNT\fR PIV data
objects of \fISIZE\fR bytes each.  Any existing \fByb\fR data on the card is
erased.
.PP
By default \fBformat\fR expects an ECDH key to already exist in the chosen
PIV slot (verified via its X.509 certificate).  Pass \fB\-\-generate\fR to
create a new P-256 key pair and a self-signed certificate on the card.
.PP
\fBformat\fR must be run once before \fBstore\fR, \fBfetch\fR, or any other
command that accesses the store."#,
            r#".SH EXAMPLES
.PP
First-time setup \(em generate a key and format with defaults:
.RS
.nf
yb format \-\-generate
.fi
.RE
.PP
Compact store (10 objects, 1024 bytes each) in slot 0x83:
.RS
.nf
yb format \-c 10 \-s 1024 \-k 0x83 \-\-generate
.fi
.RE
.PP
Re-format using an existing key in slot 0x9D:
.RS
.nf
yb format \-k 0x9D
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-store\fR(1), \fByb\-fsck\fR(1), \fBykman\fR(1)"#,
        ),

        "yb-store" => (
            r#".PP
Write one or more binary blobs to the YubiKey.
Each blob is identified by a short name (at most 32 bytes).  When a
blob with the same name already exists it is replaced atomically.
.PP
Blobs are compressed before storage by default.  \fByb\fR tries both
brotli (level 11) and xz (preset 9) and keeps the smaller result;
if neither algorithm reduces the size the blob is stored uncompressed.
Pass \fB\-\-no\-compress\fR to skip compression entirely (useful for
already-compressed data such as JPEG, ZIP, or existing brotli/xz
archives).
.PP
Blobs are encrypted by default using AES-256-GCM with a key derived via
ECDH from the public key stored in the configured PIV slot.  Pass
\fB\-\-unencrypted\fR to skip encryption (use with care)."#,
            r#".SH EXAMPLES
.PP
Store a file (blob name = basename):
.RS
.nf
yb store secret.key
.fi
.RE
.PP
Store with an explicit name:
.RS
.nf
yb store \-n mykey /path/to/key.pem
.fi
.RE
.PP
Store several files at once:
.RS
.nf
yb store a.key b.key c.key
.fi
.RE
.PP
Pipe from stdin:
.RS
.nf
pass show mysite | yb store \-\-name mysite
.fi
.RE
.PP
Store unencrypted (plain-text blob):
.RS
.nf
yb store \-\-unencrypted config.toml
.fi
.RE
.PP
Store without compression (e.g. already-compressed binary):
.RS
.nf
yb store \-\-no\-compress archive.tar.xz
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-fetch\fR(1), \fByb\-remove\fR(1), \fByb\-fsck\fR(1)"#,
        ),

        "yb-fetch" => (
            r#".PP
Retrieve one or more blobs from the YubiKey.
Names and glob patterns are accepted; each matched blob is written to a
file in the current directory (or \fIOUTPUT_DIR\fR) using the blob name as
the filename.
.PP
Use \fB\-\-stdout\fR or \fB\-\-output\fR when exactly one blob is selected and
you need direct control over the destination."#,
            r#".SH EXAMPLES
.PP
Fetch a single blob to the current directory:
.RS
.nf
yb fetch secret.key
.fi
.RE
.PP
Fetch to a specific file:
.RS
.nf
yb fetch \-o /tmp/key.pem mykey
.fi
.RE
.PP
Print to stdout (pipe-friendly):
.RS
.nf
yb fetch \-\-stdout mypassword | xclip
.fi
.RE
.PP
Fetch all blobs matching a glob into a directory:
.RS
.nf
yb fetch \-O ./restore '*.key'
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-store\fR(1), \fByb\-list\fR(1)"#,
        ),

        "yb-list" => (
            r#".PP
List the names of all blobs currently stored on the YubiKey.
An optional glob pattern filters the output.
.PP
The default output is one name per line, suitable for scripting.
\fB\-\-long\fR adds an encryption flag, chunk count, modification time,
and plaintext size."#,
            r#".SH LONG FORMAT
In long format each line contains:
.TP
Flag
\fB\-\fR for an encrypted blob, \fBP\fR for a plaintext (unencrypted) blob.
.TP
Chunks
Number of PIV objects consumed by this blob.
.TP
Date
Modification time (month, day, time for recent blobs; year for older).
.TP
Size
Plaintext size in bytes.
.TP
Name
Blob name.
.SH EXAMPLES
.PP
List all blobs:
.RS
.nf
yb list
.fi
.RE
.PP
Long listing, newest first:
.RS
.nf
yb list \-l \-t
.fi
.RE
.PP
Filter by glob:
.RS
.nf
yb list '*.key'
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-fetch\fR(1), \fByb\-remove\fR(1)"#,
        ),

        "yb-remove" => (
            r#".PP
Delete one or more blobs from the YubiKey.
Blob names and glob patterns are accepted; all matching blobs are
removed in a single write pass.
.PP
The operation is destructive and cannot be undone without the original
plaintext."#,
            r#".SH EXAMPLES
.PP
Remove a single blob:
.RS
.nf
yb remove secret.key
.fi
.RE
.PP
Remove all blobs whose names end in \fB.bak\fR:
.RS
.nf
yb remove '*.bak'
.fi
.RE
.PP
Remove if present, silently do nothing if absent:
.RS
.nf
yb remove \-\-ignore\-missing maybe.key
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-list\fR(1), \fByb\-fsck\fR(1)"#,
        ),

        "yb-fsck" => (
            r#".PP
Read the store header and all PIV objects without decrypting any blob,
then print a summary and check for structural anomalies.
.PP
\fBfsck\fR exits with status 0 if the store is clean and 1 if any warning
is detected (duplicate blob names, orphaned continuation chunks).  It
does not repair damage; use \fByb remove\fR to clean up corrupt blobs."#,
            r#".SH OUTPUT
Without \fB\-\-verbose\fR, two summary lines are printed:
.PP
.RS
.nf
Store: <n> objects x <size> bytes, slot 0x<xx>, age <n>
Blobs: <n> stored, <n> objects free (~<n> bytes available)
Status: OK   (or a count of warnings)
.fi
.RE
.PP
With \fB\-\-verbose\fR, a per-object dump is prepended showing raw metadata
fields for each PIV object (age, chunk position, blob name, size, etc.).
.SH EXAMPLES
.PP
Quick sanity check:
.RS
.nf
yb fsck
.fi
.RE
.PP
Full object dump:
.RS
.nf
yb fsck \-\-verbose
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-format\fR(1), \fByb\-remove\fR(1)"#,
        ),

        "yb-select" => (
            r#".PP
Interactively select one YubiKey from all connected devices and print
its serial number to stdout.  Intended for use in scripts:
.PP
.RS
.nf
yb \-\-serial "$(yb select)" store myfile
.fi
.RE
.PP
If only one YubiKey is connected the serial is printed immediately
without displaying the picker.  If multiple YubiKeys are connected and
the process is attached to a TTY, a single-line carousel is rendered on
stderr: use \fB\(la\fR/\fB\(ra\fR (or \fBj\fR/\fBk\fR) to cycle through devices
and \fBEnter\fR to confirm.  The currently highlighted device flashes its
LED to help identify it physically.  Press \fBEsc\fR or \fBCtrl\-C\fR to cancel.
.PP
If multiple YubiKeys are connected but stderr is not a TTY, the command
exits with an error."#,
            r#".SH EXAMPLES
.PP
Print the serial number of the selected YubiKey:
.RS
.nf
yb select
.fi
.RE
.PP
Print the PC/SC reader name instead:
.RS
.nf
yb select \-\-reader
.fi
.RE
.PP
Use in a script to target a specific YubiKey:
.RS
.nf
yb \-\-serial "$(yb select)" store secret.key
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fByb\-list\-readers\fR(1)"#,
        ),

        "yb-list-readers" => (
            r#".PP
Print all PC/SC reader names visible to the pcscd daemon, one per line.
This command does not require a YubiKey to be connected and bypasses
\fBContext\fR construction entirely, so it works even when no card is present."#,
            r#".SH EXAMPLES
.PP
List readers:
.RS
.nf
yb list-readers
.fi
.RE
.PP
Use the reader name with another command:
.RS
.nf
yb \-r "Yubico YubiKey OTP+FIDO+CCID 00 00" list
.fi
.RE
.SH SEE ALSO
\fByb\fR(1), \fBpcsc_scan\fR(1)"#,
        ),

        _ => ("", ""),
    }
}

fn write_man(dir: &std::path::Path, cmd: &clap::Command, page_name: &str) {
    let man = clap_mangen::Man::new(cmd.clone())
        .title(page_name.to_uppercase())
        .section("1")
        .date("2026-03")
        .source("yb")
        .manual("User Commands");

    let mut buf = Vec::new();
    man.render(&mut buf).expect("man page rendering failed");

    // Append extra sections if available.
    let (desc_extra, extra) = extra_sections(page_name);
    if !desc_extra.is_empty() || !extra.is_empty() {
        // Insert desc_extra after the .SH DESCRIPTION line (replace the clap one-liner).
        let text = String::from_utf8(buf).expect("man page is not utf-8");
        let patched = if !desc_extra.is_empty() {
            patch_description(&text, desc_extra)
        } else {
            text
        };
        let mut result = patched;
        if !extra.is_empty() {
            result.push('\n');
            result.push_str(extra);
            result.push('\n');
        }
        buf = result.into_bytes();
    }

    let dest = dir.join(format!("{page_name}.1"));
    std::fs::write(&dest, &buf).expect("cannot write man page");
    eprintln!("Written: {}", dest.display());
}

/// Replace the one-liner DESCRIPTION body with `extra`.
/// The clap-generated DESCRIPTION section looks like:
///   .SH DESCRIPTION\n<one line>\n
/// We keep the .SH DESCRIPTION header and replace the body.
fn patch_description(src: &str, extra: &str) -> String {
    // Find .SH DESCRIPTION, then replace everything until the next .SH
    let marker = ".SH DESCRIPTION\n";
    if let Some(desc_start) = src.find(marker) {
        let body_start = desc_start + marker.len();
        // Find the next section header after DESCRIPTION.
        let next_sh = src[body_start..].find("\n.SH ");
        let (before_body, after_body) = if let Some(rel) = next_sh {
            let abs = body_start + rel + 1; // keep the leading \n of next .SH
            (&src[..body_start], &src[abs..])
        } else {
            (&src[..body_start], "")
        };
        format!("{before_body}{extra}\n{after_body}")
    } else {
        src.to_owned()
    }
}
