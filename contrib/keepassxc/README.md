<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Trying KeePassXC with a vault on a YubiKey

An experimental KeePassXC that keeps your password database **on a
YubiKey**, instead of in a file: opening it needs the YubiKey and its PIN,
and no copy of the database is left on the computer's disk.  It is a
proposal for the KeePassXC project, built on
[yb](https://github.com/douzebis/yb) (its C library, libyubiblob).

**This is a prototype.**  Keep your usual database file as a backup, and
use a YubiKey whose PIV application you can set up for this (see step 2).
Linux only for now.

## What you need

- Linux, with PC/SC running (`pcscd`; on NixOS: `services.pcscd.enable =
  true;`).
- A YubiKey 5 (any firmware 5.x).
- [Nix](https://nixos.org/download/) (recommended: it provides everything
  else), or the build tools listed under "Without Nix".

## 1. Build KeePassXC

```shell
git clone --branch feature/yubikey-storage https://github.com/douzebis/keepassxc
cd keepassxc
curl -LO https://raw.githubusercontent.com/douzebis/yb/main/contrib/keepassxc/shell.nix
nix-shell
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DKPXC_FEATURE_YUBIBLOB=ON
ninja -C build
```

The first `nix-shell` downloads and builds its dependencies (Qt, and
libyubiblob and the `yb` command from yb's release): it takes a while
once.

### Without Nix

Install KeePassXC's build dependencies for your distribution (see
KeePassXC's `INSTALL.md`), Rust and `cargo-c`, then libyubiblob, then
KeePassXC:

```shell
cargo install cargo-c --locked
git clone --branch yubiblob-v0.1.0 https://github.com/douzebis/yb
(cd yb/rust && cargo cinstall -p yubiblob --release --prefix ~/.local --libdir lib)
export PKG_CONFIG_PATH=~/.local/lib/pkgconfig:$PKG_CONFIG_PATH

git clone --branch feature/yubikey-storage https://github.com/douzebis/keepassxc
cd keepassxc
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DKPXC_FEATURE_YUBIBLOB=ON
ninja -C build
```

## 2. Set up the YubiKey for yb

You need the `yb` command, version 0.6.0 or later.

- **With Nix:** the `nix-shell` of step 1 already provides it (from the
  same yb release as libyubiblob).  In that shell:

  ```shell
  yb format
  ```

- **With Cargo** (any Linux; needs Rust 1.86 or later, `pkg-config` and
  the PC/SC development files, e.g. `libpcsclite-dev` on Debian and
  Ubuntu, `pcsc-lite-devel` on Fedora):

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

## 3. Create a database on the YubiKey

Quit any KeePassXC already running (it would take over the new one), then
start the one you built, with the YubiKey connected:

```shell
./build/src/keepassxc
```

**Database → New Database…**, then go through the wizard as usual (name,
encryption settings, master password).  When it saves, KeePassXC asks
where: choose **On the YubiKey…**, accept or change the proposed name
(`.kdbx` is added), and enter the YubiKey's PIN.  The database now lives
on the YubiKey; `yb ls -l` lists it.

To put an existing database on the YubiKey instead, open it, then
**Database → Save As… → On the YubiKey…**.  Save As leaves the original
file where it was: keep it as a backup, or delete it.

A name already used on the YubiKey is replaced only after you confirm.
The YubiKey holds about 50 KB in all, and saving needs room for a second
copy of the database while it writes, so a database of up to about 20 KB
is comfortable.

From the command line, `./build/src/cli/keepassxc-cli db-create -p
yubikey:/Test.kdbx` does the same (master password twice, then the PIN;
it replaces a database of the same name without asking).

Optionally, keep the database's master password on the YubiKey too, so
that it opens with the YubiKey and the PIN alone (a trade-off: the master
password then no longer adds a separate factor):

```shell
read -rs pw && printf '%s' "$pw" | yb store -n Test.passwd; unset pw
```

## 4. Use it

- **Database → Open Database…** (or the button on the welcome screen):
  with the YubiKey connected, a list offers "A file…", then the databases
  on the YubiKey, e.g. `Test.kdbx (on the YubiKey)`.  Pick one, enter the
  YubiKey's PIN, then the master password (unless it is stored on the
  YubiKey).  With several YubiKeys connected, choose one by its serial
  number.
- **Saving is automatic:** a few seconds after your last change, and at
  once when you lock or close the database, or quit.  Writing to the
  YubiKey takes a few seconds.  Pulling it out during a save loses
  nothing: the previous version stays.
- **Unlocking after a lock** needs no PIN, unless the database changed on
  the YubiKey meanwhile.
- The database never touches the disk: KeePassXC holds it in memory, as
  it always does once unlocked.

To check: add an entry, quit KeePassXC, start it again and reopen
`Test.kdbx` from the YubiKey: the entry is there.

## Good to know

- A desktop notification "YubiKey is waiting for a touch" may flash on the
  unlock screen if you run `yubikey-touch-detector`: it is KeePassXC
  probing the YubiKey's challenge-response slots, as it always does; no
  touch is needed.
- To get your database back as a file at any time:
  `yb fetch -o ~/Test-copy.kdbx Test.kdbx` (it stays encrypted by
  its master password, as any KeePassXC database).
- Feedback is welcome: what worked, what did not, how large your database
  is, how the saving delay feels.
