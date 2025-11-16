# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import sys
import click
import getpass
from typing import BinaryIO
from click.shell_completion import CompletionItem

from yb import orchestrator
from yb.piv import HardwarePiv


# === FETCH ====================================================================


def complete_blob_names(ctx, param, incomplete):
    """
    Shell completion callback for blob names.

    Queries the YubiKey store to provide auto-completion for blob names.
    Returns empty list if YubiKey is not accessible or if multiple devices
    are present without explicit selection.
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
                # (require explicit --serial/--reader)
                if len(devices) > 1:
                    return []

                # Single device - auto-select it
                _, _, reader = devices[0]

            except RuntimeError:
                # Fallback to legacy list_readers() if ykman not available
                readers = piv.list_readers()

                if len(readers) == 0:
                    return []

                # If multiple readers without selection, return empty
                if len(readers) > 1:
                    return []

                # Single reader - auto-select it
                reader = readers[0]

        # List blobs from YubiKey
        blobs = orchestrator.list_blobs(reader=reader, piv=piv)
        blob_names = [name for name, _, _, _, _ in blobs]

        # Filter by incomplete text and return as CompletionItem objects
        return [
            CompletionItem(name)
            for name in blob_names
            if name.startswith(incomplete)
        ]

    except Exception:
        # If anything goes wrong (no YubiKey, permissions, etc.), return empty list
        # Shell completion should never fail loudly
        return []


@click.command(
    'fetch',
    help='''
        Retrieve one or more named blobs from the YubiKey.

        By default, the blob is written to standard output unless an output file
        is specified with -o.

        With -x/--extract, multiple blobs can be fetched and written to files
        named after the blob names.
    ''',
)
@click.option(
    '-o', '--output',
    type=click.File('wb'),
    required=False,
    help='Write the retrieved blob to the specified file.'
         ' If omitted, output is written to standard output.'
         ' Cannot be used with -x.',
)
@click.option(
    '-x', '--extract',
    is_flag=True,
    help='Extract multiple blobs to files named after the blob names.'
         ' Cannot be used with -o.',
)
@click.argument(
    'names',
    nargs=-1,
    required=True,
    shell_complete=complete_blob_names,
)
@click.pass_context
def cli_fetch(ctx,
        output: BinaryIO | None,
        extract: bool,
        names: tuple[str, ...],
    ) -> None:
    ''''''

    reader: str = ctx.obj['reader']
    piv = ctx.obj['piv']
    debug: bool = ctx.obj.get('debug', False)

    # Validate options
    if extract and output:
        raise click.ClickException("Cannot use both -x/--extract and -o/--output")

    if not extract and len(names) > 1:
        raise click.ClickException(
            f"Multiple blob names provided ({len(names)}) but -x/--extract not specified. "
            "Use -x to extract multiple blobs to files."
        )

    if not extract and len(names) != 1:
        raise click.ClickException("Exactly one blob name required (or use -x for multiple)")

    # Check which blobs are encrypted to determine if PIN is needed
    all_blobs = orchestrator.list_blobs(reader=reader, piv=piv)
    blob_encryption_status = {name: is_encrypted for name, _, is_encrypted, _, _ in all_blobs}

    # Determine if any requested blob is encrypted
    needs_pin = False
    for name in names:
        if name in blob_encryption_status and blob_encryption_status[name]:
            needs_pin = True
            break

    # Prompt for PIN only if needed
    pin: str | None = None
    if needs_pin:
        try:
            pin = getpass.getpass("Please enter User PIN for encrypted blob(s): ")
            if pin == "":
                pin = None
        except (EOFError, KeyboardInterrupt):
            pin = None

    # Fetch blobs
    if extract:
        # Extract mode: write each blob to file named after blob
        for name in names:
            try:
                payload = orchestrator.fetch_blob(
                    reader=reader,
                    piv=piv,
                    name=name,
                    pin=pin,
                    debug=debug,
                )

                if payload is None:
                    raise click.ClickException(f'Cannot find object {name}')

                # Write to file with blob name
                with open(name, 'wb') as f:
                    f.write(payload)

                click.echo(f"Extracted {name} ({len(payload)} bytes)", err=True)

            except ValueError as e:
                raise click.ClickException(str(e)) from e
            except RuntimeError as e:
                raise click.ClickException(str(e)) from e
    else:
        # Single blob mode (backward compatible)
        assert len(names) > 0  # click says option is required
        name = names[0]
        try:
            payload = orchestrator.fetch_blob(
                reader=reader,
                piv=piv,
                name=name,
                pin=pin,
                debug=debug,
            )

            if payload is None:
                raise click.ClickException(f'Cannot find object {name}')

        except ValueError as e:
            raise click.ClickException(str(e)) from e
        except RuntimeError as e:
            raise click.ClickException(str(e)) from e

        # Write output
        if output is None:
            sys.stdout.buffer.write(payload)
        else:
            output.write(payload)
