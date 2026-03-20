// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

mod auxiliaries;
mod cli;
mod context;
mod crypto;
mod orchestrator;
mod piv;
mod store;

use clap::{Parser, Subcommand};
use context::Context;

// ---------------------------------------------------------------------------
// Top-level CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "yb", about = "Secure blob storage on a YubiKey", version)]
struct Cli {
    /// YubiKey serial number.
    #[arg(short = 's', long = "serial")]
    serial: Option<u32>,

    /// PC/SC reader name (legacy; prefer --serial).
    #[arg(short = 'r', long = "reader")]
    reader: Option<String>,

    /// Management key (48 hex chars).
    #[arg(short = 'k', long = "key")]
    management_key: Option<String>,

    /// YubiKey PIN.
    #[arg(long = "pin")]
    pin: Option<String>,

    /// Enable debug output.
    #[arg(long = "debug")]
    debug: bool,

    /// Allow insecure default credentials (not recommended).
    #[arg(long = "allow-defaults")]
    allow_defaults: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
    /// List PC/SC readers.
    ListReaders(cli::list_readers::ListReadersArgs),
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let result = run(cli);
    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = Context::new(
        cli.serial,
        cli.reader,
        cli.management_key,
        cli.pin,
        cli.debug,
        cli.allow_defaults,
    )?;

    match cli.command {
        Commands::Format(args) => cli::format::run(&ctx, &args),
        Commands::Store(args) => cli::store::run(&ctx, &args),
        Commands::Fetch(args) => cli::fetch::run(&ctx, &args),
        Commands::List(args) => cli::list::run(&ctx, &args),
        Commands::Remove(args) => cli::remove::run(&ctx, &args),
        Commands::Fsck(args) => cli::fsck::run(&ctx, &args),
        Commands::ListReaders(args) => cli::list_readers::run(&ctx, &args),
    }
}
