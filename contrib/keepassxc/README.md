<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Trying KeePassYB: a password database on a YubiKey

[KeePassYB](https://github.com/douzebis/keepassyb) is KeePassXC with one
addition: it keeps your password database **on a YubiKey**, instead of in
a file.  Opening it needs the YubiKey and the master password, and no copy
of the database is left on the computer's disk.  It is built on
[yb](https://github.com/douzebis/yb) (its C library, libyubiblob).  It is
not affiliated with or endorsed by the KeePassXC Team.

**This is a prototype.**  Keep your usual database file as a backup, and
use a YubiKey whose PIV application you can set up for this (see step 2).
This guide is for Linux.

## What you need

- Linux, with PC/SC running (`pcscd`; on NixOS: `services.pcscd.enable =
  true;`).
- A YubiKey 5 (any firmware 5.x).
- [Nix](https://nixos.org/download/) (recommended: it provides everything
  else), or the build tools listed under "Without Nix".

## 1. Build KeePassYB

```shell
git clone https://github.com/douzebis/keepassyb
cd keepassyb
curl -LO https://raw.githubusercontent.com/douzebis/yb/main/contrib/keepassxc/shell.nix
nix-shell
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build
```

The first `nix-shell` downloads and builds its dependencies (Qt, and
libyubiblob and the `yb` command from yb's release): it takes a while
once.

### Without Nix

Install KeePassXC's build dependencies for your distribution (see
KeePassYB's `INSTALL.md`), Rust, `cargo-c`, and libfido2's and PC/SC's
development files (Debian and Ubuntu: `libfido2-dev libpcsclite-dev`;
Fedora: `libfido2-devel pcsc-lite-devel`).  Then build libyubiblob, then
KeePassYB:

```shell
cargo install cargo-c --locked
git clone --branch v0.7.0 https://github.com/douzebis/yb
(cd yb/rust && cargo cinstall -p yubiblob --release --prefix ~/.local --libdir lib)
export PKG_CONFIG_PATH=~/.local/lib/pkgconfig:$PKG_CONFIG_PATH

git clone https://github.com/douzebis/keepassyb
cd keepassyb
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build
```

## 2. Set up the YubiKey for yb

You need the `yb` command, version 0.7.0 or later: older versions don't
take the YubiKey's lock, and could disturb KeePassYB's saves.

- **With Nix:** the `nix-shell` of step 1 already provides it (from the
  same yb release as libyubiblob).  In that shell:

  ```shell
  yb format
  ```

- **With Cargo** (needs Rust 1.86 or later, `pkg-config`, and the
  development files listed under "Without Nix"):

  ```shell
  cargo install yb --locked
  ~/.cargo/bin/yb format
  ```

  Below, `yb` is `~/.cargo/bin/yb` unless `~/.cargo/bin` is in your
  `PATH`.

`yb format` explains what it will do and asks before changing anything.
It sets up yb's store in the YubiKey's PIV application, a key in slot 0x82,
and has the YubiKey keep its management key, unlocked by your PIN.  It
offers to change a factory-default PIN and PUK.  It does not touch other
PIV slots (e.g. an SSH key in 9a), nor FIDO2, OTP or OATH.

`yb format --post-quantum` makes a store protected by the YubiKey's FIDO2
application instead (see yb's README): saving then needs the FIDO2 PIN
and a touch.

## 3. Create a database on the YubiKey

Start KeePassYB with the YubiKey connected (it runs next to an installed
KeePassXC without interfering):

```shell
./build/src/keepassyb
```

**Database → New Database…**, then go through the wizard as usual (name,
encryption settings, master password).  When it saves, KeePassYB asks
where: choose **On the YubiKey…**, accept or change the proposed name
(`.kdbx` is added), and enter the YubiKey's PIN.  The database now lives
on the YubiKey; `yb ls -l` lists it.

To put an existing database on the YubiKey instead, open it, then
**Database → Save As… → On the YubiKey…**.  Save As leaves the original
file where it was: keep it as a backup, or delete it.

To save room, a database first saved to the YubiKey keeps no history of
its entries (KeePassYB says so; Database settings → History raises it).
A name already used on the YubiKey is replaced only after you confirm.
The YubiKey holds about 50 KB in all, and saving needs room for a second
copy of the database while it writes, so a database of up to about 20 KB
is comfortable.

From the command line, `./build/src/cli/keepassyb-cli db-create -p
yubikey:/Test.kdbx` does the same (master password twice, then the PIN;
it replaces a database of the same name without asking).

## 4. Use it

- **Database → Open Database…** (or the button on the welcome screen):
  with the YubiKey connected, a list offers "A file…", then the databases
  on the YubiKey, e.g. `Test.kdbx (on the YubiKey)`.  Pick one and enter
  the master password: opening needs no PIN.  With several YubiKeys
  connected, choose one by its serial number.
- **Saving is automatic,** a quarter of a second after a change, and at
  once when you lock or close the database, or quit.  The PIN is asked at
  the first save, and kept until the database is locked.  Writing to the
  YubiKey takes a few seconds; a dialog says so, and says when to touch
  the YubiKey.  Pulling it out during a save loses nothing: the previous
  version stays.
- **Only real changes are written:** expanding a group, or opening and
  closing without a change, writes nothing.
- **Changed elsewhere:** if another program (another computer, `yb store`)
  changed the database on the YubiKey meanwhile, nothing is overwritten:
  KeePassYB asks, as KeePassXC does for a file changed on disk (merge,
  overwrite, discard).
- The database never touches the disk: KeePassYB holds it in memory, as
  KeePassXC always does once unlocked.

To check: add an entry, quit KeePassYB, start it again and reopen
`Test.kdbx` from the YubiKey: the entry is there.

On a post-quantum store, KeePassYB can also keep the master password on
the YubiKey ("Remember the master password on this YubiKey" in the
unlock dialog), so that the database opens with the FIDO2 PIN and a touch
instead (a trade-off: the master password then no longer adds a separate
factor).

## Good to know

- To get your database back as a file at any time:
  `yb fetch -o ~/Test-copy.kdbx Test.kdbx` (it stays encrypted by its
  master password, as any KeePassXC database).
- `QT_LOGGING_RULES="keepassyb.yubikey=true" ./build/src/keepassyb` logs
  each YubiKey operation and its duration (no PIN, password or content).
- What KeePassYB changes in KeePassXC:
  [KEEPASSYB.md](https://github.com/douzebis/keepassyb/blob/keepassyb/KEEPASSYB.md).
- Feedback is welcome, in [KeePassYB's
  issues](https://github.com/douzebis/keepassyb/issues): what worked, what
  did not, how large your database is.
