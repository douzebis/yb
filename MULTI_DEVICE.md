<!--
SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Multi-Device Selection: Technical Analysis and Improvement Paths

## Executive Summary

The current yb implementation uses **PC/SC reader names** for device selection,
which provides functional but suboptimal user experience when multiple YubiKeys
are present. This document analyzes the technical mechanisms for device
identification and proposes several solution paths ranging from minimal
enhancements to comprehensive redesign.

**Key Finding**: YubiKey **serial numbers** are the proper mechanism for stable,
user-friendly device identification, but current implementation lacks support
for serial-based selection.

---

## Table of Contents

1. [Current State: PC/SC Reader Names](#current-state-pcsc-reader-names)
2. [Proper Approach: Serial Number Support](#proper-approach-serial-number-support)
3. [Detailed Comparison: PC/SC vs Serial](#detailed-comparison-pcsc-vs-serial)
4. [Solution Paths](#solution-paths)
   - [Path 1: Minimal Enhancement](#path-1-minimal-enhancement)
   - [Path 2: Serial Number Support](#path-2-serial-number-support)
   - [Path 3: Interactive Selection](#path-3-interactive-selection)
   - [Path 4: Configuration-Based Aliases](#path-4-configuration-based-aliases)
   - [Path 5: Migration to ykman Library](#path-5-migration-to-ykman-library)
   - [Path 6: Intelligent Auto-Discovery](#path-6-intelligent-auto-discovery)
5. [Implementation Recommendations](#implementation-recommendations)

---

## Current State: PC/SC Reader Names

### Technical Mechanism

The current implementation (`main.py:68-96`) uses the PC/SC (Personal
Computer/Smart Card) subsystem for device identification:

```python
readers = Piv.list_readers()  # Calls: yubico-piv-tool --action list-readers
if len(readers) > 1:
    raise click.ClickException(
        'Multiple PIV readers are connected:\n'
        f'{yaml.dump(readers)}\n'
        'Use the --reader option to pick one.'
    )
```

**PC/SC Reader Naming Convention**:
- Format: `"Yubico YubiKey <interfaces> <slot> <instance>"`
- Example: `"Yubico YubiKey OTP+FIDO+CCID 00 00"`
- Components:
  - **Vendor**: "Yubico"
  - **Product**: "YubiKey"
  - **Interfaces**: Active USB interfaces (OTP, FIDO, CCID combinations)
  - **Slot/Instance**: Numeric identifiers (meaning unclear, likely PC/SC internal)

### How PC/SC Assignment Works

PC/SC is a standard API for smart card access. When a smart card reader
(including YubiKeys in CCID mode) connects:

1. **Driver Detection**: System detects USB device via VID/PID
2. **Reader Registration**: PC/SC daemon (`pcscd` on Linux) registers the device
3. **Name Generation**: Reader name constructed from:
   - USB iProduct string (contains interface configuration)
   - Slot/instance numbers (to distinguish multiple identical devices)
4. **Name Exposure**: Applications query readers via PC/SC API

**Key Limitation**: Reader names are **PC/SC-assigned**, not YubiKey-intrinsic.
They reflect the PC/SC subsystem's view, not the device's identity.

### Current User Experience

**Single YubiKey** (smooth):
```bash
$ yb list
- myblob
# Automatically selects the only connected device
```

**Multiple YubiKeys** (friction):
```bash
$ yb list
Error: Multiple PIV readers are connected:
- Yubico YubiKey OTP+FIDO+CCID 00 00
- Yubico YubiKey OTP+FIDO+CCID 01 00

Use the --reader option to pick one.

$ yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" list
# Must copy/paste exact reader name (quotes required due to spaces)
```

**Verification Flow**:
```bash
$ yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" fetch secret
Confirm by entering your PIN...
# YubiKey flashes
# User enters PIN
# Operation proceeds
```

### Problems Identified

1. **Reader Name Instability**:
   - Changes if USB interfaces reconfigured (e.g., disabling OTP)
   - Example: `"...OTP+FIDO+CCID..."` → `"...FIDO+CCID..."` after `ykman config usb --disable OTP`
   - User's saved reader name becomes invalid

2. **Non-Unique Identification**:
   - Two identical YubiKeys show as `"...00 00"` and `"...01 00"`
   - Numeric suffixes have no semantic meaning to user
   - No way to know which physical device is which

3. **Poor Usability**:
   - Long, unwieldy names (30+ characters)
   - Requires quoting in shell
   - Copy/paste-heavy workflow
   - Error-prone (typos, wrong quotes)

4. **No Persistence**:
   - Cannot assign meaningful names like "work-key" or "backup-key"
   - Cannot remember "which 00 00 is which"
   - Scripts break when devices reconnect in different order

5. **Weak Verification**:
   - PIN prompt confirms *a* YubiKey is present
   - Doesn't cryptographically prove device identity
   - User might enter PIN on wrong device

---

## Proper Approach: Serial Number Support

### Technical Mechanism

Every YubiKey has a **hardware-embedded serial number**, a unique 32-bit integer
assigned during manufacturing.

**Retrieval Methods**:

1. **Via PIV APDU Command**:
   ```
   Command: 00:f8:00:00
   Response: 4 bytes (little-endian serial number)
   Example: 0x00AE17CB → 11409355 (decimal)
   ```

2. **Via yubico-piv-tool**:
   ```bash
   $ yubico-piv-tool --reader "..." -a status
   Version:        5.2.7
   Serial Number:  12345678
   CHUID:          No data available
   CCC:            No data available
   ```

3. **Via ykman (YubiKey Manager)**:
   ```bash
   $ ykman list --serials
   12345678
   87654321

   $ ykman --device 12345678 info
   Device type: YubiKey 5 NFC
   Serial number: 12345678
   Firmware version: 5.2.7
   ```

4. **Via Attestation Certificate** (YubiKey 5.0+):
   - PIV attestation statements include serial number
   - Embedded in X.509 certificate extensions
   - Cryptographically signed by Yubico CA

**Key Properties**:

- **Unique**: No two YubiKeys share the same serial
- **Stable**: Never changes across reboots, reconnections, reconfigurations
- **Persistent**: Survives firmware updates, interface changes
- **Discoverable**: Can be queried without prior knowledge
- **Human-Readable**: Short integer (typically 8 digits)
- **Physical**: Often printed on device case + accessible as 2D barcode

### Why Serial Numbers Are Superior

| Aspect | PC/SC Reader Name | Serial Number |
|--------|-------------------|---------------|
| **Uniqueness** | No (identical models same name) | Yes (hardware-unique) |
| **Stability** | No (changes with config) | Yes (immutable) |
| **Brevity** | 30+ chars | 8 digits |
| **Memorability** | Low (cryptic suffixes) | High (can write on label) |
| **Persistence** | No (reconnect order matters) | Yes (always same) |
| **Physical ID** | No | Yes (printed on case) |
| **Scriptability** | Poor (quoting, escaping) | Good (simple integer) |

### User Experience with Serial Numbers

**Ideal workflow**:

```bash
# Discovery
$ yb list-devices
Serial    Model          Firmware  PC/SC Reader
12345678  YubiKey 5 NFC  5.2.7     Yubico YubiKey OTP+FIDO+CCID 00 00
87654321  YubiKey 5C     5.4.3     Yubico YubiKey OTP+FIDO+CCID 01 00

# Selection by serial
$ yb --serial 12345678 list
- work-blob
- backup-keys

# Environment variable for default
$ export YB_SERIAL=12345678
$ yb list
- work-blob
- backup-keys

# Verification includes serial
$ yb --serial 12345678 fetch secret
Using YubiKey serial 12345678
Confirm by entering your PIN...
[YubiKey flashes]
Enter PIN: ****
```

**Benefits**:
- User writes serial on physical label → easy identification
- Serial in scripts never breaks (stable across reconnects)
- Error messages can say "YubiKey 12345678 not found" (actionable)
- Can map serial to purpose: 12345678=work, 87654321=personal

---

## Detailed Comparison: PC/SC vs Serial

### Technical Architecture

**PC/SC Approach (Current)**:
```
┌─────────────┐
│  yb CLI     │
└──────┬──────┘
       │ subprocess: yubico-piv-tool --action list-readers
       ▼
┌──────────────────┐
│ yubico-piv-tool  │
└──────┬───────────┘
       │ PC/SC API
       ▼
┌──────────────────┐
│ pcscd (daemon)   │
└──────┬───────────┘
       │ USB
       ▼
┌──────────────────┐
│ YubiKey (CCID)   │
└──────────────────┘

Reader name = PC/SC internal identifier
Not stable across configurations
```

**Serial Number Approach (Proposed)**:
```
┌─────────────┐
│  yb CLI     │
└──────┬──────┘
       │ 1. Enumerate readers (PC/SC)
       │ 2. Query serial for each (PIV APDU)
       │ 3. Match target serial
       ▼
┌──────────────────┐
│ yubico-piv-tool  │
│ -a status        │  ← Parses "Serial Number: ..." line
└──────┬───────────┘
       │ APDU: 00:f8:00:00
       ▼
┌──────────────────┐
│ YubiKey (PIV)    │
│ Returns: serial  │  ← Hardware register
└──────────────────┘

Serial = Hardware-embedded value
Stable, unique, device-intrinsic
```

### Implementation Complexity

**PC/SC (Current)**:
- **Code**: ~10 lines (already implemented)
- **Dependencies**: None (yubico-piv-tool already required)
- **Edge Cases**: Minimal (just string matching)
- **Maintenance**: Low (PC/SC standard stable)

**Serial Number (Basic)**:
- **Code**: ~30 lines (parse `yubico-piv-tool -a status` output)
- **Dependencies**: None (same tool)
- **Edge Cases**: Moderate (parsing, error handling)
- **Maintenance**: Low (serial APDU stable)

**Serial Number (via ykman)**:
- **Code**: ~15 lines (native Python API)
- **Dependencies**: +1 (yubikey-manager library)
- **Edge Cases**: Fewer (library handles details)
- **Maintenance**: Low (Yubico maintains library)

### Performance Implications

**PC/SC Enumeration**:
```bash
$ time yubico-piv-tool --action list-readers
Yubico YubiKey OTP+FIDO+CCID 00 00
Yubico YubiKey OTP+FIDO+CCID 01 00

real    0m0.012s
```

**Serial Retrieval (per device)**:
```bash
$ time yubico-piv-tool --reader "..." -a status
Version:        5.2.7
Serial Number:  12345678
...

real    0m0.084s
```

**Impact**: With 2 devices, serial-based selection adds ~170ms overhead
(enumerate readers + query 2 serials). Acceptable for CLI tool.

**Optimization**: Cache serial-to-reader mapping in context object (query once
per invocation, not per command).

### Security Considerations

**PC/SC Reader Name**:
- **Privacy**: Reader names don't expose device identity
- **Tracking**: Cannot track specific device across systems
- **Authentication**: Name is not authenticated (can be spoofed via custom PC/SC driver)

**Serial Number**:
- **Privacy**: Serial number uniquely identifies device
  - Concern: Command history, logs, scripts expose which YubiKey used
  - Mitigation: Users who value privacy can still use `--reader`
- **Tracking**: Serial allows tracking device usage across contexts
  - Example: Corporate YubiKey serial 12345678 used on personal system (visible in logs)
- **Authentication**: Serial itself is not authenticated
  - YubiKey attestation certificates sign serial, proving authenticity
  - Could verify attestation to ensure serial not spoofed

**Recommendation**: Support both methods, document privacy implications.

---

## Solution Paths

### Path 1: Minimal Enhancement

**Goal**: Improve error messages without changing selection mechanism.

**Technical Implementation**:

Add serial number display when multiple readers detected:

```python
# In main.py:cli()
if len(readers) > 1:
    # NEW: Query serial for each reader
    reader_info = []
    for reader in readers:
        serial = get_yubikey_serial(reader)  # NEW helper function
        reader_info.append({
            'reader': reader,
            'serial': serial
        })

    raise click.ClickException(
        'Multiple PIV readers are connected:\n'
        f'{yaml.dump(reader_info)}\n'
        'Use the --reader option to pick one.'
    )

# NEW: Helper function
def get_yubikey_serial(reader: str) -> int | None:
    try:
        result = subprocess.run(
            ['yubico-piv-tool', '--reader', reader, '-a', 'status'],
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        for line in result.stdout.splitlines():
            if 'Serial Number:' in line:
                return int(line.split(':')[1].strip())
    except (subprocess.CalledProcessError, ValueError, subprocess.TimeoutExpired):
        return None
    return None
```

**User Experience Improvement**:

Before:
```bash
$ yb list
Error: Multiple PIV readers are connected:
- Yubico YubiKey OTP+FIDO+CCID 00 00
- Yubico YubiKey OTP+FIDO+CCID 01 00

Use the --reader option to pick one.
```

After:
```bash
$ yb list
Error: Multiple PIV readers are connected:
- reader: Yubico YubiKey OTP+FIDO+CCID 00 00
  serial: 12345678
- reader: Yubico YubiKey OTP+FIDO+CCID 01 00
  serial: 87654321

Use the --reader option to pick one.
```

**Benefits**:
- User can write down serial → physical label → identify device
- Error message more informative
- No breaking changes (still use `--reader`)
- Minimal code change (~20 lines)

**Limitations**:
- Still requires full reader name
- No serial-based selection
- Adds 80ms per device to error path

**Effort**: 1-2 hours

---

### Path 2: Serial Number Support

**Goal**: Add `--serial` option as first-class selection mechanism.

**Technical Implementation**:

```python
# In main.py
@click.group()
@click.option('-r', '--reader', type=str, help='PC/SC reader name')
@click.option('-s', '--serial', type=int, help='YubiKey serial number')
@click.option('-x', '--no-verify', is_flag=True)
@click.pass_context
def cli(ctx, reader: str | None, serial: int | None, no_verify: bool) -> None:
    # Validate mutually exclusive options
    if reader and serial:
        raise click.ClickException('Cannot specify both --reader and --serial')

    chosen_reader: str

    if serial:
        # NEW: Serial-based selection
        chosen_reader = find_reader_by_serial(serial)
        if not no_verify:
            print(f'Using YubiKey serial {serial}', file=sys.stderr)
            print('Confirm by entering your PIN...', file=sys.stderr)
            if not Piv.verify_reader(chosen_reader, 0x9a):
                raise click.ClickException('Could not verify the PIN.')

    elif reader:
        # Existing: Reader name selection
        chosen_reader = reader
        if not no_verify:
            print('Confirm by entering your PIN...', file=sys.stderr)
            if not Piv.verify_reader(chosen_reader, 0x9a):
                raise click.ClickException('Could not verify the PIN.')

    else:
        # Existing: Auto-select logic
        readers = Piv.list_readers()
        if len(readers) == 0:
            raise click.ClickException('No PIV reader is connected.')
        elif len(readers) == 1:
            chosen_reader = readers[0]
        else:
            # Show serials in multi-reader error
            reader_info = []
            for r in readers:
                s = get_yubikey_serial(r)
                reader_info.append({'reader': r, 'serial': s})
            raise click.ClickException(
                'Multiple PIV readers are connected:\n'
                f'{yaml.dump(reader_info)}\n'
                'Use --serial <number> or --reader <name> to pick one.'
            )

    ctx.ensure_object(dict)
    ctx.obj['reader'] = chosen_reader

# NEW: Serial → Reader mapping
def find_reader_by_serial(target_serial: int) -> str:
    readers = Piv.list_readers()
    for reader in readers:
        serial = get_yubikey_serial(reader)
        if serial == target_serial:
            return reader
    raise click.ClickException(
        f'No YubiKey found with serial number {target_serial}\n'
        f'Connected devices: {[get_yubikey_serial(r) for r in readers]}'
    )

# NEW: Helper (same as Path 1)
def get_yubikey_serial(reader: str) -> int | None:
    # ... (implementation from Path 1)
```

**User Experience Improvement**:

```bash
# Discovery
$ yb list  # Multiple devices
Error: Multiple PIV readers are connected:
- reader: Yubico YubiKey OTP+FIDO+CCID 00 00
  serial: 12345678
- reader: Yubico YubiKey OTP+FIDO+CCID 01 00
  serial: 87654321

Use --serial <number> or --reader <name> to pick one.

# Selection by serial (NEW)
$ yb --serial 12345678 list
Using YubiKey serial 12345678
Confirm by entering your PIN...
Enter PIN: ****
- work-blob
- backup-keys

# Selection by reader (still works)
$ yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" list
# ... (same as before)

# Error handling
$ yb --serial 99999999 list
Error: No YubiKey found with serial number 99999999
Connected devices: [12345678, 87654321]
```

**Benefits**:
- Short, memorable identifier (8 digits vs 30+ chars)
- Stable across reconnections, reconfigurations
- Can write serial on physical label
- Backward compatible (--reader still works)
- Better error messages (shows available serials)

**Limitations**:
- Adds ~80ms lookup overhead per invocation
- Serial query can fail (timeout, PIV error)
- Privacy: Serial exposed in commands, logs

**Effort**: 4-6 hours (implementation + testing + error handling)

---

### Path 3: Interactive Selection

**Goal**: Prompt user to select device when multiple present (no manual option required).

**Technical Implementation**:

```python
# In main.py
@click.group()
@click.option('-r', '--reader', type=str, help='PC/SC reader name')
@click.option('-s', '--serial', type=int, help='YubiKey serial number')
@click.option('-x', '--no-verify', is_flag=True)
@click.option('--batch', is_flag=True, help='Non-interactive mode (error on ambiguity)')
@click.pass_context
def cli(ctx, reader: str | None, serial: int | None, no_verify: bool, batch: bool) -> None:
    # ... (same validation as Path 2)

    if not reader and not serial:
        readers = Piv.list_readers()
        if len(readers) == 0:
            raise click.ClickException('No PIV reader is connected.')
        elif len(readers) == 1:
            chosen_reader = readers[0]
        else:
            # Multiple readers: prompt or error
            if batch:
                # Batch mode: fail fast
                reader_info = []
                for r in readers:
                    reader_info.append({'reader': r, 'serial': get_yubikey_serial(r)})
                raise click.ClickException(
                    'Multiple PIV readers are connected:\n'
                    f'{yaml.dump(reader_info)}\n'
                    'Use --serial <number> or --reader <name> to pick one.'
                )
            else:
                # Interactive mode: prompt user (NEW)
                chosen_reader = prompt_for_device(readers)

    # ... (rest of logic)

# NEW: Interactive device selection
def prompt_for_device(readers: list[str]) -> str:
    print('Multiple YubiKeys detected:\n', file=sys.stderr)

    devices = []
    for i, reader in enumerate(readers, start=1):
        serial = get_yubikey_serial(reader)
        devices.append({'index': i, 'serial': serial, 'reader': reader})

        # Compact display
        serial_str = str(serial) if serial else 'Unknown'
        print(f'  [{i}] Serial {serial_str}', file=sys.stderr)

    print('', file=sys.stderr)

    while True:
        try:
            choice = click.prompt(
                f'Select device [1-{len(devices)}]',
                type=int,
                err=True
            )
            if 1 <= choice <= len(devices):
                selected = devices[choice - 1]
                print(f"Using YubiKey serial {selected['serial']}\n", file=sys.stderr)
                return selected['reader']
            else:
                print(f'Please enter a number between 1 and {len(devices)}', file=sys.stderr)
        except click.Abort:
            raise click.ClickException('Device selection cancelled')
```

**User Experience Improvement**:

```bash
# Interactive mode (default)
$ yb list
Multiple YubiKeys detected:

  [1] Serial 12345678
  [2] Serial 87654321

Select device [1-2]: 1
Using YubiKey serial 12345678

Confirm by entering your PIN...
Enter PIN: ****
- work-blob
- backup-keys

# Batch/script mode (explicit selection required)
$ yb --batch list
Error: Multiple PIV readers are connected:
- reader: Yubico YubiKey OTP+FIDO+CCID 00 00
  serial: 12345678
- reader: Yubico YubiKey OTP+FIDO+CCID 01 00
  serial: 87654321

Use --serial <number> or --reader <name> to pick one.

# Non-interactive with selection
$ yb --serial 12345678 list
# (no prompt, proceeds directly)
```

**Benefits**:
- Zero-friction multi-device workflow (no flags needed)
- User-friendly number selection (1, 2, 3 vs long reader names)
- Serial numbers displayed for labeling
- Graceful degradation (single device = auto-select)
- Script-safe with `--batch` flag

**Limitations**:
- Interactive prompts bad for scripts/automation (hence --batch)
- Adds complexity to CLI flow
- May surprise users expecting error (breaking change in behavior)

**Effort**: 6-8 hours (interactive flow + batch mode + testing)

**Design Consideration**: Make interactive prompt opt-in via environment variable:
```bash
export YB_INTERACTIVE=1  # Enable interactive selection
yb list  # Prompts if multiple devices
```

---

### Path 4: Configuration-Based Aliases

**Goal**: Allow users to assign memorable names to YubiKeys via config file.

**Technical Implementation**:

```python
# NEW: config.py
import os
from pathlib import Path
import yaml

class Config:
    def __init__(self):
        self.config_path = Path.home() / '.config' / 'yb' / 'config.yaml'
        self.devices = {}
        self.load()

    def load(self):
        if self.config_path.exists():
            with open(self.config_path) as f:
                data = yaml.safe_load(f)
                self.devices = data.get('devices', {})

    def get_serial(self, alias: str) -> int | None:
        """Get serial number for device alias."""
        device = self.devices.get(alias)
        if device:
            return device.get('serial')
        return None

    def get_alias(self, serial: int) -> str | None:
        """Get alias for serial number."""
        for alias, device in self.devices.items():
            if device.get('serial') == serial:
                return alias
        return None

# In main.py
@click.group()
@click.option('-r', '--reader', type=str, help='PC/SC reader name')
@click.option('-s', '--serial', type=int, help='YubiKey serial number')
@click.option('-d', '--device', type=str, help='Device alias from config')  # NEW
@click.option('-x', '--no-verify', is_flag=True)
@click.pass_context
def cli(ctx, reader: str | None, serial: int | None, device: str | None, no_verify: bool) -> None:
    # Validate mutually exclusive
    options_set = sum([reader is not None, serial is not None, device is not None])
    if options_set > 1:
        raise click.ClickException('Cannot specify multiple selection options')

    chosen_reader: str

    if device:
        # NEW: Alias-based selection
        config = Config()
        resolved_serial = config.get_serial(device)
        if not resolved_serial:
            raise click.ClickException(
                f'Unknown device alias: {device}\n'
                f'Available aliases: {list(config.devices.keys())}\n'
                f'Edit {config.config_path} to add devices.'
            )
        chosen_reader = find_reader_by_serial(resolved_serial)
        alias = device
        print(f'Using device "{alias}" (serial {resolved_serial})', file=sys.stderr)

    elif serial:
        # Serial-based selection (show alias if exists)
        chosen_reader = find_reader_by_serial(serial)
        config = Config()
        alias = config.get_alias(serial)
        if alias:
            print(f'Using YubiKey serial {serial} (alias: "{alias}")', file=sys.stderr)
        else:
            print(f'Using YubiKey serial {serial}', file=sys.stderr)

    # ... (rest of selection logic)

# NEW: Command to manage config
@click.command('config')
@click.argument('action', type=click.Choice(['list', 'add', 'remove', 'edit']))
def cli_config(action: str) -> None:
    """Manage device configuration and aliases."""
    config = Config()

    if action == 'list':
        if not config.devices:
            print('No devices configured.')
            print(f'Edit {config.config_path} or use "yb config add"')
        else:
            print('Configured devices:\n')
            for alias, device in config.devices.items():
                serial = device.get('serial', 'Unknown')
                desc = device.get('description', '')
                print(f'  {alias}: serial {serial}')
                if desc:
                    print(f'    {desc}')

    elif action == 'add':
        # Interactive add
        readers = Piv.list_readers()
        if not readers:
            raise click.ClickException('No YubiKey connected')

        # Show available devices
        print('Connected YubiKeys:\n')
        devices = []
        for i, reader in enumerate(readers, start=1):
            serial = get_yubikey_serial(reader)
            devices.append({'serial': serial, 'reader': reader})
            print(f'  [{i}] Serial {serial}')

        choice = click.prompt('\nSelect device [1-{}]'.format(len(devices)), type=int)
        selected = devices[choice - 1]

        alias = click.prompt('Enter alias (e.g., "work", "backup")', type=str)
        description = click.prompt('Description (optional)', type=str, default='')

        config.devices[alias] = {
            'serial': selected['serial'],
            'description': description
        }

        # Save
        config.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config.config_path, 'w') as f:
            yaml.dump({'devices': config.devices}, f)

        print(f'\nAdded device alias "{alias}" → serial {selected["serial"]}')
        print(f'Config saved to {config.config_path}')

    # ... (implement 'remove' and 'edit')

cli.add_command(cli_config)
```

**Configuration File** (`~/.config/yb/config.yaml`):

```yaml
devices:
  work:
    serial: 12345678
    description: "Blue YubiKey - Work laptop"

  backup:
    serial: 87654321
    description: "Black YubiKey - Stored in safe"

  personal:
    serial: 11111111
    description: "Red YubiKey - Personal use"
```

**User Experience Improvement**:

```bash
# Initial setup (one-time)
$ yb config add
Connected YubiKeys:

  [1] Serial 12345678
  [2] Serial 87654321

Select device [1-2]: 1
Enter alias (e.g., "work", "backup"): work
Description (optional): Blue YubiKey - Work laptop

Added device alias "work" → serial 12345678
Config saved to /home/user/.config/yb/config.yaml

# Usage with alias
$ yb --device work list
Using device "work" (serial 12345678)
Confirm by entering your PIN...
- work-blob
- backup-keys

# List configured devices
$ yb config list
Configured devices:

  work: serial 12345678
    Blue YubiKey - Work laptop

  backup: serial 87654321
    Black YubiKey - Stored in safe

# Environment variable for default device
$ export YB_DEVICE=work
$ yb list
Using device "work" (serial 12345678)
# ...

# Mix of configured and unconfigured
$ yb --serial 99999999 list  # New device, no alias yet
Using YubiKey serial 99999999
# ...
```

**Benefits**:
- Human-friendly names ("work" vs "12345678")
- Self-documenting (descriptions explain purpose)
- Persistent across all yb invocations
- Discoverable (`yb config list`)
- Natural workflow: setup once, use everywhere
- Complements serial numbers (aliases → serials under the hood)

**Limitations**:
- Requires config file management
- Config can become stale (device replaced, serial changed)
- Users must remember aliases (but `yb config list` helps)
- Additional commands to maintain (`yb config add/remove/edit`)

**Effort**: 10-12 hours (config management + YAML handling + validation + docs)

**Dependencies**: PyYAML (already required)

---

### Path 5: Migration to ykman Library

**Goal**: Replace `yubico-piv-tool` subprocess calls with native Python API from `yubikey-manager`.

**Technical Implementation**:

```python
# NEW: piv_ykman.py (replaces piv.py)
from yubikey_manager import list_all_devices
from yubikey_manager.device import YubiKeyDevice
from yubikey_manager.piv import PivSession

class Piv:
    """YubiKey PIV operations using ykman library."""

    @classmethod
    def list_devices(cls) -> list[tuple[int, str, YubiKeyDevice]]:
        """
        List all connected YubiKeys with serial numbers.

        Returns:
            List of (serial, name, device) tuples
        """
        devices = []
        for device, info in list_all_devices():
            serial = info.serial
            name = f"{info.device_name} (Serial: {serial})"
            devices.append((serial, name, device))
        return devices

    @classmethod
    def connect_by_serial(cls, serial: int) -> YubiKeyDevice:
        """Find and connect to YubiKey by serial number."""
        for device, info in list_all_devices():
            if info.serial == serial:
                return device
        raise ValueError(f"No YubiKey found with serial {serial}")

    @classmethod
    def read_object(cls, device: YubiKeyDevice, object_id: int) -> bytes:
        """Read PIV data object."""
        with device.open_connection(PivSession) as session:
            return session.get_object(object_id)

    @classmethod
    def write_object(cls, device: YubiKeyDevice, object_id: int, data: bytes) -> None:
        """Write PIV data object."""
        with device.open_connection(PivSession) as session:
            session.put_object(object_id, data)

    @classmethod
    def verify_pin(cls, device: YubiKeyDevice, pin: str) -> bool:
        """Verify PIV PIN."""
        with device.open_connection(PivSession) as session:
            try:
                session.verify_pin(pin)
                return True
            except Exception:
                return False

# In main.py
@click.group()
@click.option('-s', '--serial', type=int, help='YubiKey serial number')
@click.option('-x', '--no-verify', is_flag=True)
@click.pass_context
def cli(ctx, serial: int | None, no_verify: bool) -> None:
    devices = Piv.list_devices()

    if not devices:
        raise click.ClickException('No YubiKey connected.')

    if serial:
        # Find by serial
        device = None
        for s, name, dev in devices:
            if s == serial:
                device = dev
                break
        if not device:
            available = [s for s, _, _ in devices]
            raise click.ClickException(
                f'No YubiKey found with serial {serial}\n'
                f'Connected devices: {available}'
            )
    else:
        # Auto-select
        if len(devices) == 1:
            serial, name, device = devices[0]
        else:
            # Show all with serials
            print('Multiple YubiKeys detected:\n', file=sys.stderr)
            for i, (s, name, _) in enumerate(devices, start=1):
                print(f'  [{i}] Serial {s}', file=sys.stderr)
            raise click.ClickException(
                'Use --serial <number> to select a device.'
            )

    # Verification
    if not no_verify:
        print(f'Using YubiKey serial {serial}', file=sys.stderr)
        pin = click.prompt('Enter PIN', hide_input=True, err=True)
        if not Piv.verify_pin(device, pin):
            raise click.ClickException('Invalid PIN')

    ctx.ensure_object(dict)
    ctx.obj['device'] = device
    ctx.obj['serial'] = serial

# In store.py
@classmethod
def from_piv_device(cls, device: YubiKeyDevice) -> Store:
    # Read object 0
    raw_data = Piv.read_object(device, OBJECT_ID_ZERO)
    # ... (rest of parsing)
```

**Dependencies**:

```toml
# pyproject.toml
dependencies = [
  "click",
  "PyYAML",
  "cryptography",
  "yubikey-manager>=5.0.0"  # NEW
]
```

**User Experience Improvement**:

```bash
# Native serial support (no parsing needed)
$ yb list
Multiple YubiKeys detected:

  [1] Serial 12345678
  [2] Serial 87654321

Use --serial <number> to select a device.

$ yb --serial 12345678 list
Using YubiKey serial 12345678
Enter PIN: ****
- work-blob

# Better error messages (library provides rich info)
$ yb --serial 99999999 list
Error: No YubiKey found with serial 99999999
Connected devices:
  - Serial 12345678 (YubiKey 5 NFC, Firmware 5.2.7)
  - Serial 87654321 (YubiKey 5C, Firmware 5.4.3)

# No PC/SC reader names exposed at all
# (abstracted by ykman library)
```

**Benefits**:
- **Native serial support**: No subprocess parsing, direct API access
- **Richer metadata**: Firmware version, model, capabilities
- **Better error handling**: Library handles edge cases
- **Cleaner code**: Python API vs subprocess + text parsing
- **Active maintenance**: Yubico maintains ykman library
- **Cross-platform**: Library handles OS differences
- **Future-proof**: New YubiKey features available via library updates

**Limitations**:
- **Additional dependency**: yubikey-manager (large, ~50 dependencies)
- **Breaking change**: Internal API completely different (refactor required)
- **Testing complexity**: Need mock YubiKey devices for tests
- **Regression risk**: Behavior changes if library API differs from yubico-piv-tool

**Effort**: 20-30 hours (full refactor of piv.py, crypto.py, testing)

**Risk**: High (large change, potential for subtle bugs)

**Recommendation**: Consider as long-term goal, not initial implementation.

---

### Path 6: Intelligent Auto-Discovery

**Goal**: Automatically select the correct YubiKey based on stored blob names.

**Technical Implementation**:

```python
# In main.py
@click.group()
@click.option('-s', '--serial', type=int, help='YubiKey serial number')
@click.option('--auto', is_flag=True, help='Auto-discover device by blob name')
@click.pass_context
def cli(ctx, serial: int | None, auto: bool) -> None:
    # ... (existing selection logic)

    ctx.ensure_object(dict)
    ctx.obj['serial'] = serial
    ctx.obj['auto'] = auto

# In cli_fetch.py
@click.command('fetch')
@click.argument('name', type=str)
@click.option('-o', '--output', type=click.File('wb'))
@click.pass_context
def cli_fetch(ctx, name: str, output: BinaryIO | None) -> None:
    serial = ctx.obj.get('serial')
    auto = ctx.obj.get('auto')

    if not serial and auto:
        # NEW: Auto-discovery
        serial = discover_device_with_blob(name)
        if serial:
            print(f'Auto-discovered: blob "{name}" found on YubiKey serial {serial}', file=sys.stderr)
            ctx.obj['serial'] = serial
        else:
            raise click.ClickException(
                f'Blob "{name}" not found on any connected YubiKey'
            )

    # ... (rest of fetch logic)

# NEW: Auto-discovery helper
def discover_device_with_blob(blob_name: str) -> int | None:
    """Scan all connected YubiKeys for a blob with the given name."""
    devices = Piv.list_devices()  # Assumes Path 5 (ykman) or similar

    for serial, _, device in devices:
        try:
            # Load store
            store = Store.from_piv_device(device)
            store.sanitize()

            # Check for blob
            for obj in store.objects:
                if (obj.object_age != 0
                    and obj.chunk_pos_in_blob == 0
                    and obj.blob_name == blob_name):
                    return serial
        except Exception:
            # Device read failed, skip
            continue

    return None
```

**User Experience Improvement**:

```bash
# Traditional: Must specify device
$ yb --serial 12345678 fetch work-blob
Using YubiKey serial 12345678
Enter PIN: ****
[blob contents]

# Auto-discovery: Finds the right device
$ yb --auto fetch work-blob
Scanning connected YubiKeys...
Auto-discovered: blob "work-blob" found on YubiKey serial 12345678
Enter PIN: ****
[blob contents]

# Multiple devices, blob only on one
$ yb --auto fetch personal-key
Scanning connected YubiKeys...
Auto-discovered: blob "personal-key" found on YubiKey serial 87654321
Enter PIN: ****
[blob contents]

# Blob exists on multiple devices (ambiguous)
$ yb --auto fetch backup-key
Error: blob "backup-key" found on multiple YubiKeys:
  - Serial 12345678
  - Serial 87654321

Use --serial <number> to select a device.

# Environment variable to make auto default
$ export YB_AUTO_DISCOVER=1
$ yb fetch work-blob
# (automatically scans and finds)
```

**Benefits**:
- **Zero-config**: No need to remember which blob is on which device
- **Natural workflow**: "Get my SSH key" vs "Get my SSH key from device 12345678"
- **Resilient**: Works even if user forgets which YubiKey has what
- **Multi-device friendly**: Naturally handles multiple YubiKeys with different contents

**Limitations**:
- **Slow**: Must scan all devices (read all objects), ~200ms per device
- **PIN prompts**: Might prompt for PIN on wrong device first (then retry)
- **Ambiguity**: Fails if blob exists on multiple devices
- **Security**: Leaks blob name existence across devices (privacy concern)
- **Read-only**: Doesn't help with `store` operation (which device to write to?)

**Effort**: 8-10 hours (scanning logic + ambiguity resolution + caching)

**Use Case**: Best for users with multiple YubiKeys storing disjoint sets of blobs.

**Optimization**: Cache serial → blob names mapping to avoid repeated scans:

```python
# Cache in ~/.cache/yb/device_index.yaml
devices:
  12345678:
    blobs:
      - work-blob
      - ssh-key
    last_scan: 2025-11-15T10:30:00
  87654321:
    blobs:
      - personal-key
      - backup-key
    last_scan: 2025-11-15T10:30:00

# Invalidate cache on store/remove operations
```

---

## Implementation Recommendations

### Recommended Path: Incremental Adoption

Implement in stages to balance effort vs value:

**Stage 1: Foundation** (Path 1 + Path 2)
- Show serial numbers in error messages (Path 1)
- Add `--serial` option (Path 2)
- **Effort**: 6-8 hours
- **Value**: Immediate UX improvement, stable identifiers

**Stage 2: Usability** (Path 3)
- Interactive device selection
- `--batch` flag for scripts
- **Effort**: 6-8 hours
- **Value**: Frictionless multi-device workflow

**Stage 3: Power Users** (Path 4)
- Configuration file support
- Device aliases
- `yb config` command
- **Effort**: 10-12 hours
- **Value**: Enterprise/power user workflows, documentation

**Stage 4: Advanced** (Path 6, optional)
- Auto-discovery by blob name
- Device index caching
- **Effort**: 8-10 hours
- **Value**: Niche use case, nice-to-have

**Future Consideration** (Path 5)
- Migration to ykman library
- **Effort**: 20-30 hours
- **Value**: Long-term maintainability, but high risk/effort
- **Recommendation**: Evaluate after 1-2 years, when codebase stable

### Backward Compatibility

All paths maintain compatibility with existing `--reader` option:

```bash
# Old scripts continue to work
yb --reader "Yubico YubiKey OTP+FIDO+CCID 00 00" list

# New scripts use serial
yb --serial 12345678 list

# Both supported indefinitely
```

### Environment Variable Support

Standardize environment variables across all paths:

```bash
YB_SERIAL=12345678        # Default serial number
YB_DEVICE=work            # Default device alias (Path 4)
YB_READER="..."           # Default reader name (existing)
YB_AUTO_DISCOVER=1        # Enable auto-discovery (Path 6)
YB_INTERACTIVE=1          # Enable interactive prompt (Path 3)
```

Priority order: CLI flag > Environment variable > Auto-select/Prompt

### Testing Strategy

**Unit Tests**:
- Serial number parsing (edge cases: invalid format, timeout)
- Serial → reader mapping (not found, multiple matches)
- Config file loading (invalid YAML, missing file)

**Integration Tests**:
- Mock multiple PC/SC readers
- Mock serial number responses
- Test all selection paths (reader, serial, alias, interactive)

**Manual Testing** (require physical devices):
- Two YubiKeys connected simultaneously
- Verify serial-based selection
- Verify interactive prompt
- Verify PIN verification flow

### Documentation Updates

**README.md**:
- Update "Multiple YubiKeys" section
- Examples with `--serial` flag
- Link to MULTI_DEVICE.md for details

**DESIGN.md**:
- Add section on device selection mechanisms
- Link to MULTI_DEVICE.md for deep dive

**Man Page** (future):
- Document all selection options
- Examples for common scenarios

---

## Conclusion

**Current state**: PC/SC reader names provide functional but poor UX for multi-device scenarios.

**Proper solution**: Serial number-based selection provides stable, user-friendly device identification.

**Recommended approach**: Incremental implementation starting with `--serial` support (Path 2), followed by interactive selection (Path 3) and optional configuration (Path 4).

**Effort vs Value**:
- **High ROI**: Paths 1-3 (total ~20 hours, major UX improvement)
- **Medium ROI**: Path 4 (~12 hours, power users benefit)
- **Low ROI**: Path 5 (~30 hours, high risk for marginal gain)
- **Niche ROI**: Path 6 (~10 hours, specialized use case)

**Timeline**:
- Stages 1-2: 2-3 weeks part-time development
- Stage 3: Additional 1-2 weeks
- Full implementation (Stages 1-4): 1-2 months

**Key Success Metrics**:
- User can operate on correct YubiKey without consulting docs
- Serial numbers enable physical device labeling
- Scripts using serial numbers stable across reconnections
- Multi-device workflows feel natural, not error-prone
