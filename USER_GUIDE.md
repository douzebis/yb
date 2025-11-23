# yb User Guide

**yb** is a command-line tool for securely storing encrypted or unencrypted binary data on your YubiKey using its PIV (Personal Identity Verification) application.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Concepts](#basic-concepts)
4. [Initial Setup](#initial-setup)
5. [Storing Data](#storing-data)
6. [Retrieving Data](#retrieving-data)
7. [Managing Blobs](#managing-blobs)
8. [Working with Multiple YubiKeys](#working-with-multiple-yubikeys)
9. [Advanced Features](#advanced-features)
10. [Troubleshooting](#troubleshooting)
11. [Security Best Practices](#security-best-practices)
12. [Getting Help](#getting-help)

---

## Quick Start

```bash
# 1. Initialize your YubiKey for blob storage
yb format --generate

# 2. Store encrypted data
echo "My secret data" | yb store --encrypted mysecret

# 3. Retrieve the data
yb fetch mysecret
# (You'll be prompted for your YubiKey PIN)

# 4. List all stored blobs
yb ls

# 5. Remove a blob
yb rm mysecret
```

---

## Installation

### Prerequisites

**Required Tools**:
- `yubico-piv-tool`: PIV operations
- `pkcs11-tool` (from OpenSC): PKCS#11 operations
- Python 3.12 or later

**Required Python Libraries**:
- `click`: CLI framework
- `cryptography`: Encryption operations
- `PyYAML`: Output formatting
- `yubikey-manager`: Multi-device support (recommended)

### Using Nix (Recommended)

```bash
# Clone the repository
git clone https://github.com/douzebis/yb.git
cd yb

# Enter development shell
nix-shell -A devShell

# yb is now available
yb --help
```

### Manual Installation

```bash
# Install system dependencies
sudo apt-get install yubico-piv-tool opensc  # Debian/Ubuntu
# OR
brew install yubico-piv-tool opensc  # macOS

# Install Python package
pip install -e .

# Verify installation
yb --help
```

---

## Basic Concepts

### What is a Blob?

A **blob** (binary large object) is any data you want to store on your YubiKey:
- Text files
- Configuration files
- SSH keys
- Certificates
- Any binary data

Each blob has:
- **Name**: Unique identifier (1-255 characters)
- **Payload**: The actual data (up to ~36 KB with default settings)
- **Encryption**: Can be encrypted or unencrypted
- **Metadata**: Size, modification time, chunk count

### Storage Capacity

With default settings (12 objects, 3052 bytes each):
- **Total capacity**: ~36 KB
- **Per blob overhead**: ~23 bytes (metadata)
- **Largest single blob**: ~36 KB (uses all objects)

You can store:
- Many small files (dozens of 1 KB files)
- A few medium files (several 10 KB files)
- One large file (~36 KB)

### Encryption

**Encrypted blobs** (default):
- Protected with hybrid ECDH + AES-256-CBC encryption
- Private key never leaves your YubiKey
- Requires PIN to decrypt (fetch)
- Does NOT require PIN to encrypt (store)

**Unencrypted blobs**:
- Stored in plaintext
- Faster to store and retrieve
- No PIN required
- Suitable for non-sensitive data

---

## Initial Setup

### Step 1: Format Your YubiKey

Initialize the blob storage on your YubiKey:

```bash
yb format --generate
```

This will:
1. **Prompt for confirmation** (PIN verification)
2. **Generate an EC P-256 key pair** in slot 0x9e (Card Authentication)
3. **Create a self-signed certificate** for the key
4. **Initialize the blob store** with 12 empty objects

**Options**:
```bash
# Custom object count (more capacity, max 16)
yb format --generate --object-count 16

# Use different PIV slot for encryption key
yb format --generate --key-slot 82  # Retired Key 1

# Don't generate new key (use existing key)
yb format --no-generate --key-slot 82
```

### Step 2: Verify Setup

Check that the store was initialized:

```bash
yb fsck
```

You should see:
```yaml
reader: Yubico YubiKey OTP+FIDO+CCID 00 00
yblob_magic: f2ed5f0b
object_size_in_store: 3052
object_count_in_store: 12
store_encryption_key_slot: 0x9e
store_age: 0
```

---

## Storing Data

### Basic Store Operation

Store a file as an encrypted blob:

```bash
# From a file
yb store myfile < data.txt

# From stdin
echo "Hello, world!" | yb store greeting

# Specify file explicitly
yb store --input data.txt myfile
```

### Store Options

**Encryption**:
```bash
# Encrypted (default - recommended for sensitive data)
yb store --encrypted secret

# Unencrypted (faster, no PIN required for fetch)
yb store --unencrypted public-data
```

**Input Sources**:
```bash
# From file
yb store --input file.txt blobname

# From stdin
cat file.txt | yb store blobname

# Auto-name from filename
yb store --input document.pdf
# Creates blob named "document.pdf"
```

### Examples

**Store SSH private key**:
```bash
yb store --encrypted --input ~/.ssh/id_ed25519 ssh-key
```

**Store configuration file**:
```bash
yb store --unencrypted --input ~/.config/app/settings.json app-config
```

**Store password from password manager**:
```bash
pass show github.com/token | yb store --encrypted github-token
```

**Store GPG key backup**:
```bash
gpg --export-secret-keys --armor user@example.com | yb store gpg-backup
```

---

## Retrieving Data

### Basic Fetch Operation

Retrieve a blob by name:

```bash
# To stdout
yb fetch myfile

# To file
yb fetch myfile > recovered.txt

# Specify output file
yb fetch --output recovered.txt myfile
```

**If blob is encrypted**, you'll be prompted for your YubiKey PIN:
```
Please enter User PIN for encrypted blob(s): ******
```

### Extract Multiple Blobs

Fetch multiple blobs at once:

```bash
# Extract to files with blob names
yb fetch --extract ssh-key app-config github-token

# Output:
# Extracted ssh-key (3243 bytes)
# Extracted app-config (512 bytes)
# Extracted github-token (40 bytes
```

### Shell Completion

Enable tab completion for blob names:

```bash
# For bash
eval "$(_YB_COMPLETE=bash_source yb)"

# For zsh
eval "$(_YB_COMPLETE=zsh_source yb)"
```

---

## Managing Blobs

### List All Blobs

See what's stored on your YubiKey:

```bash
yb ls
```

**Output format**:
```
-  1        7  2025-06-01 13:22  sensitive-data
U  1       10  2025-06-01 13:36  public-data
-  3     5432  2025-06-02 09:15  large-file
```

**Columns**:
1. **Encryption**: `-` = encrypted, `U` = unencrypted
2. **Chunks**: Number of PIV objects used
3. **Size**: Unencrypted size in bytes
4. **Modified**: Last modification timestamp
5. **Name**: Blob name

### Remove a Blob

Delete a blob by name:

```bash
yb rm blobname
```

This will:
1. **Prompt for confirmation** (PIN verification)
2. **Remove all chunks** of the named blob
3. **Free the space** for new blobs

**Example**:
```bash
yb rm old-backup
```

### Check Store Health

Inspect low-level store details:

```bash
yb fsck
```

This shows:
- Store metadata (magic number, encryption slot, age counter)
- Each object's status (empty, head chunk, body chunk)
- Chunk linkage information
- Blob metadata for head chunks

Useful for:
- Debugging storage issues
- Verifying store integrity
- Understanding space usage

**Example output**:
```yaml
reader: Yubico YubiKey OTP+FIDO+CCID 00 00
yblob_magic: f2ed5f0b
...
---

<object_index_in_store>: 0
<is_dirty>: false
yblob_magic: 0xf2ed5f0b
...
chunk_pos_in_blob: 0
next_chunk_index_in_store: 1
blob_modification_date: Sun Jan  1 12:00:00 2025
payload_size: 5432
blob_name: large-file
```

---

## Working with Multiple YubiKeys

### Device Selection Methods

**Method 1: Serial Number (Recommended)**:
```bash
# Auto-completion for serial numbers
yb --serial <TAB>
# Shows: 12345678 -- YubiKey 5.7.1

yb --serial 12345678 ls
```

**Method 2: PC/SC Reader Name (Legacy)**:
```bash
yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" ls
```

**Method 3: Auto-Selection**:
If only one YubiKey is connected, it's selected automatically:
```bash
yb ls
# Output: Auto-selected YubiKey 12345678 (version 5.7.1)
```

### Interactive Selection

When multiple YubiKeys are connected without explicit selection:

```bash
$ yb ls

Select a YubiKey:

  → YubiKey 12345678 (v5.7.1)  # ← Currently selected (LED flashing)
    YubiKey 87654321 (v5.4.3)

Use ↑/↓ arrows to navigate, ENTER to select, Ctrl-C to cancel
```

The selected YubiKey's LED will flash continuously while highlighted.

### Shell Completion for Serial Numbers

```bash
# Enable completion
eval "$(_YB_COMPLETE=bash_source yb)"

# Now:
yb --serial <TAB>
# Shows all connected YubiKeys with versions
```

---

## Advanced Features

### Custom Store Configuration

**Change Object Count**:
```bash
# More objects = more capacity (max 16)
yb format --generate --object-count 16

# Fewer objects = less capacity but faster (min 1)
yb format --generate --object-count 8
```

**Change Object Size**:
```bash
# Smaller objects (min 512 bytes)
yb format --generate --object-size 512

# Default/maximum (3052 bytes)
yb format --generate --object-size 3052
```

**Trade-offs**:
- More/larger objects = more capacity
- Fewer/smaller objects = faster operations
- Max capacity: 16 objects × 3052 bytes ≈ 47 KB

### Custom Encryption Slot

Use a different PIV slot for the encryption key:

```bash
# Common choices:
# 9e (default): Card Authentication
# 82-95: Retired Keys (20 available)
# 9a: PIV Authentication (not recommended - used for login)
# 9c: Digital Signature (not recommended - used for signing)

yb format --generate --key-slot 82
```

**Note**: Once formatted with a specific slot, all encrypted blobs on that YubiKey use that slot's private key.

### Skip PIN Verification

For non-interactive scripts or when you trust the environment:

```bash
# Skip PIN prompt (no YubiKey LED flash)
yb -x format --generate
yb -x store blob < data
yb -x rm blob
```

**WARNING**: Only use `-x` in trusted environments. Without PIN verification:
- No confirmation that you have the correct YubiKey
- Accidental writes to wrong device possible
- Less secure

### Management Key

For write operations, you can specify a custom management key:

```bash
# Prompt for key interactively
yb --key=- format --generate
# (You'll be prompted to enter 48 hex characters)

# Provide key directly (INSECURE - visible in shell history)
yb --key=0102030405... format --generate
```

**Default**: YubiKey factory default management key is used if not specified.

### PIN-Protected Management Key Mode (Recommended)

YubiKeys can store the management key on-device, encrypted and protected by your PIN. This is the **recommended** setup for security and convenience.

**Benefits**:
- More secure than default management key
- More convenient than manually providing 48-char hex key
- You only need to remember your PIN
- Management key never leaves the YubiKey

**Setup** (one-time):
```bash
# Generate random management key and store it PIN-protected
ykman piv access change-management-key --generate --protect
```

**Usage**:
Once configured, `yb` automatically detects and uses PIN-protected mode:

```bash
# No --key needed! Management key retrieved automatically from YubiKey
yb store myfile           # Will prompt for PIN if needed
yb --pin 123456 store     # Non-interactive with PIN
```

**How it works**:
1. `yb` reads ADMIN DATA object to detect PIN-protected mode
2. When write operation needed, prompts for PIN (if not provided via `--pin`)
3. After PIN verification, reads management key from PRINTED object
4. Uses retrieved key for the operation

**Override**:
You can still explicitly provide `--key` to override PIN-protected mode:
```bash
yb --key 010203...0708 store myfile
```

**Note**: PIN-protected mode automatically uses non-default credentials, so you won't see default credential warnings.

### Debug Mode

Enable verbose debugging output:

```bash
yb --debug fetch encrypted-blob
```

Shows:
- ECDH parameters
- Encryption/decryption steps
- PKCS#11 token selection
- Payload sizes at each stage

### Self-Test

Run comprehensive end-to-end tests on your YubiKey:

```bash
# Run with default settings (200 operations)
yb --serial 12345678 self-test

# Run with custom operation count
yb --serial 12345678 self-test -n 100

# Non-interactive with credentials
yb --serial 12345678 --pin 123456 --key 010203...0708 self-test
```

**What it does**:
1. **Formats the YubiKey** (destroys all existing blob data)
2. **Performs random operations** (store/fetch/remove/list)
3. **Tests both encrypted and unencrypted blobs**
4. **Stops on first error** (if any) since state becomes unknown
5. **Reports success/failure statistics**

**WARNING**: This is a **destructive operation** that will erase all blob data on your YubiKey!

**Options**:
- `-n, --count`: Number of operations to perform (default: 200)
- All operations use 16 objects with blobs up to 16 KB

**Example output**:
```
Running 200 test operations...

[1/200, 199 remaining] STORE(session)... OK
[2/200, 198 remaining] FETCH(session)... OK
[3/200, 197 remaining] LIST... OK
...

======================================================================
YB SELF-TEST REPORT
======================================================================

Test Configuration:
  Operations: 200
  Duration: 214.9 seconds

Operation Results:
  STORE:  68 operations, 68 passed, 0 failed
  FETCH:  66 operations, 66 passed, 0 failed
  REMOVE: 38 operations, 38 passed, 0 failed
  LIST:   28 operations, 28 passed, 0 failed

  TOTAL: 200 operations, 200 passed, 0 failed

Result: ✓ ALL TESTS PASSED
======================================================================
```

**Note**: "Store is full" is treated as expected behavior (not an error) when the YubiKey reaches capacity.

---

## Troubleshooting

### "No YubiKeys found"

**Symptoms**: `yb` can't detect your YubiKey

**Solutions**:
1. **Verify YubiKey is inserted**: Check USB connection
2. **Check permissions**: May need to be in `pcscd` group (Linux)
3. **Restart pcscd service**: `sudo systemctl restart pcscd`
4. **Verify with yubico-piv-tool**: `yubico-piv-tool -a list-readers`

### "Store has bad yblob magic"

**Symptoms**: Error when running `yb ls` or other commands

**Cause**: YubiKey not formatted with `yb format`, or data corruption

**Solution**:
```bash
# Re-format the YubiKey (WARNING: destroys existing data)
yb format --generate
```

### "Cannot find object <name>"

**Symptoms**: `yb fetch` or `yb rm` says blob doesn't exist

**Solutions**:
1. **List blobs**: `yb ls` to see what's actually stored
2. **Check spelling**: Blob names are case-sensitive
3. **Verify YubiKey**: Make sure you're using correct device with `--serial`

### "Blob is encrypted but no PIN provided"

**Symptoms**: Trying to fetch encrypted blob in non-interactive context

**Solution**:
- Run `yb fetch` interactively so you can enter PIN
- Or decrypt blob with PIN and re-store as unencrypted

### "Store is full - cannot store blob"

**Symptoms**: No free objects available

**Solutions**:
1. **Remove old blobs**: `yb rm old-blob`
2. **Reformat with more objects**: `yb format --object-count 16`
3. **Compress data**: Compress before storing to reduce size

### PIN Locked

**Symptoms**: Too many incorrect PIN attempts, YubiKey locked

**Solution**:
- Reset PIN using YubiKey Manager: `ykman piv reset`
- **WARNING**: This erases all PIV data including stored blobs
- Have backups before resetting!

### Wrong YubiKey Selected (Multiple Devices)

**Symptoms**: Unexpected blobs shown or "object not found"

**Solution**:
```bash
# List all connected devices
yb --serial <TAB>

# Specify correct one explicitly
yb --serial 12345678 ls
```

---

## Security Best Practices

### Default Credential Detection

**yb automatically checks for default credentials** and refuses to operate if detected. This prevents accidental use of insecure default values.

**Default credentials checked**:
- **PIN**: 123456
- **PUK**: 12345678
- **Management Key**: 010203040506070801020304050607080102030405060708

If defaults are detected, yb will show:

```
Error: YubiKey is using default credentials (INSECURE):
  - PIN (default: 123456, 3 attempts remaining)
  - Management Key (default: 010203...)

This is a security risk. Please change your YubiKey credentials:
  - Change PIN: ykman piv access change-pin
  - Change PUK: ykman piv access change-puk
  - Change Management Key (recommended with PIN-protected mode):
    ykman piv access change-management-key --generate --protect

To proceed anyway (NOT RECOMMENDED), use --allow-defaults flag.
```

**Change all default credentials immediately**:

```bash
# Change PIN (default: 123456)
ykman piv access change-pin

# Change PUK (default: 12345678)
ykman piv access change-puk

# Change Management Key (recommended with PIN-protected mode)
ykman piv access change-management-key --generate --protect
```

**Note**: This check requires YubiKey firmware 5.3+. On older firmware, yb displays a warning but continues.

**For testing/development only**:
- Use `--allow-defaults` flag to bypass (INSECURE)
- Set `YB_SKIP_DEFAULT_CHECK=1` environment variable to skip

### Backup Your Data

**YubiKey is not a backup solution**. Hardware can fail, be lost, or have PIN locked.

**Backup strategy**:
```bash
# Export all blobs
for blob in $(yb ls | awk '{print $5}'); do
    yb fetch --output backup/$blob $blob
done

# Encrypt backup archive
tar czf - backup/ | gpg --symmetric > yubikey-backup.tar.gz.gpg
```

### Use Encryption for Sensitive Data

**Always encrypt**: SSH keys, GPG keys, passwords, tokens, personal information

**Unencrypted is OK for**: Public keys, public certificates, non-sensitive configuration

---

## Getting Help

- **Command help**: `yb --help` or `yb <command> --help`
- **Report issues**: https://github.com/douzebis/yb/issues
- **Design document**: See `DESIGN.md` for technical details
