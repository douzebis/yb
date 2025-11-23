# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from datetime import datetime
from fnmatch import fnmatch
from click.shell_completion import CompletionItem

from yb import orchestrator
from yb.piv import HardwarePiv

# === LS =======================================================================

def complete_blob_names_for_ls(ctx, param, incomplete):
    """
    Provide shell completion for blob name patterns in ls command.

    Returns all blob names that match the partial pattern.
    """
    try:
        # Get PIV interface
        piv = HardwarePiv()

        # Check if reader/serial was specified in the parent context
        reader = None
        parent_ctx = ctx.parent

        if parent_ctx and parent_ctx.params:
            # Check for --serial option
            serial = parent_ctx.params.get('serial')
            if serial is not None:
                try:
                    reader = piv.get_reader_for_serial(serial)
                except (ValueError, RuntimeError):
                    return []

            # Check for --reader option
            elif parent_ctx.params.get('reader'):
                reader = parent_ctx.params.get('reader')

        # If no reader specified via options, check for single device
        if reader is None:
            try:
                devices = piv.list_devices()

                # If no devices, return empty
                if len(devices) == 0:
                    return []

                # If multiple devices without selection, return empty
                if len(devices) > 1:
                    return []

                # Single device - use it
                _, _, reader = devices[0]

            except (RuntimeError, ImportError):
                return []

        # List all blobs
        blobs = orchestrator.list_blobs(reader=reader, piv=piv)

        # Return blob names that match the incomplete pattern
        matches = []
        for name, _, _, _, _ in blobs:
            # Filter by incomplete pattern (prefix match)
            if name.startswith(incomplete):
                matches.append(CompletionItem(name))

        return matches

    except Exception:
        # If anything fails, return empty list (don't break completion)
        return []


@click.command(
    'ls',
    help='''List blobs stored in the YubiKey, optionally filtered by pattern.

        \b
        PATTERN supports shell glob wildcards:
          *     matches everything
          ?     matches any single character
          [seq] matches any character in seq
          [!seq] matches any character not in seq

        \b
        Examples:
          yb ls              # List all blobs
          yb ls "*.txt"      # List only .txt files
          yb ls "config*"    # List blobs starting with 'config'
          yb ls "test?"      # List test1, test2, etc.

        \b
        Each entry shows the following fields:

          - Encryption status: '-' for encrypted, 'U' for unencrypted
          - Number of PIV objects used to store the blob
          - Blob size in bytes
          - Creation timestamp (YYYY-MM-DD HH:MM)
          - Blob name

        Example output:
          -  1        7  2025-06-01 13:22  sensitive-data
          U  1       10  2025-06-01 13:36  public-data''',
)
@click.argument(
    'pattern',
    type=str,
    required=False,
    default='*',
    shell_complete=complete_blob_names_for_ls,
)
@click.pass_context
def cli_list(ctx, pattern: str) -> None:
    ''''''

    reader: str = ctx.obj['reader']
    piv = ctx.obj['piv']

    # Call orchestrator
    blobs = orchestrator.list_blobs(reader=reader, piv=piv)

    # Filter blobs by pattern
    filtered_blobs = [
        (name, size, is_encrypted, mtime, chunk_count)
        for name, size, is_encrypted, mtime, chunk_count in blobs
        if fnmatch(name, pattern)
    ]

    # Format and print each blob
    for name, size, is_encrypted, mtime, chunk_count in filtered_blobs:
        bits = '-' if is_encrypted else 'U'
        count = str(chunk_count).rjust(2)
        size_str = str(size).rjust(8)
        dt = datetime.fromtimestamp(mtime)
        date = dt.strftime("%Y-%m-%d %H:%M").ljust(16)
        print(f"{bits} {count} {size_str} {date} {name}")
