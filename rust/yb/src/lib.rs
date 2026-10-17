// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

pub mod cli;
pub mod complete;

use clap::{Parser, Subcommand};
use clap_complete::engine::ArgValueCompleter;

use crate::complete::complete_serials;

/// Returns the root clap `Command` for `yb`.  Used by `yb-gen-man`.
pub fn command() -> clap::Command {
    use clap::CommandFactory as _;
    Cli::command()
}

#[derive(Parser, Debug)]
#[command(name = "yb", about = "Secure blob storage on a YubiKey", version)]
pub struct Cli {
    /// YubiKey serial number.
    #[arg(short = 's', long = "serial", add = ArgValueCompleter::new(complete_serials))]
    pub serial: Option<u32>,

    /// PC/SC reader name (legacy; prefer --serial).
    #[arg(short = 'r', long = "reader")]
    pub reader: Option<String>,

    /// Suppress informational output.
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Read the PIN from the first line of standard input; a payload read
    /// from standard input (yb store) follows it.
    #[arg(long = "pin-stdin")]
    pub pin_stdin: bool,

    /// Enable debug output.
    #[arg(long = "debug")]
    pub debug: bool,

    /// Allow insecure default credentials (not recommended).
    #[arg(long = "allow-defaults")]
    pub allow_defaults: bool,

    /// Try the FIDO2 PIN even with 3 attempts or fewer left (post-quantum
    /// stores): a blocked FIDO2 PIN cannot be unblocked.
    #[arg(long = "allow-low-pin-attempts")]
    pub allow_low_pin_attempts: bool,

    /// YubiKey PIN [deprecated, removed in yb 0.7: use YB_PIN, --pin-stdin, or the prompt].
    #[arg(long = "pin", hide = true)]
    pub pin_deprecated: Option<String>,

    /// Management key [deprecated, removed in yb 0.7: use YB_MANAGEMENT_KEY].
    #[arg(short = 'k', long = "key", hide = true)]
    pub key_deprecated: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Provision PIV objects and optionally generate an ECDH key.
    Format(cli::format::FormatArgs),
    /// Store a blob on the YubiKey.
    Store(cli::store::StoreArgs),
    /// Retrieve one or more blobs.
    Fetch(cli::fetch::FetchArgs),
    /// List blobs (alias: ls).
    #[command(alias = "ls")]
    List(cli::list::ListArgs),
    /// Remove a blob (alias: rm).
    #[command(alias = "rm")]
    Remove(cli::remove::RemoveArgs),
    /// Filesystem check — dump store metadata.
    Fsck(cli::fsck::FsckArgs),
    /// Replace the management key with a random one, kept on the YubiKey
    /// and unlocked by the PIN (the store is kept).
    RotateManagementKey(cli::rotate_management_key::RotateManagementKeyArgs),
    /// List PC/SC readers.
    ListReaders(cli::list_readers::ListReadersArgs),
    /// Interactively select a YubiKey and print its serial number.
    Select(cli::select::SelectArgs),
    /// Run a destructive end-to-end self-test on real hardware.
    #[cfg(feature = "self-test")]
    SelfTest(cli::self_test::SelfTestArgs),
}
