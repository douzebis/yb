# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
from click.shell_completion import CompletionItem

from yb import orchestrator
from yb.piv import HardwarePiv


# === REMOVE ===================================================================


def complete_blob_names_for_rm(ctx, param, incomplete):
    """
    Provide shell completion for blob names in rm command.

    Returns all blob names that match the partial input.
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
    'rm',
    help='''
        Remove a named blob from the YubiKey.

        This permanently deletes the stored blob associated with the given name.
    ''',
)
@click.argument(
    'name',
    type=str,
    shell_complete=complete_blob_names_for_rm,
)
@click.pass_context
def cli_remove(ctx,
        name: str,
    ) -> None:
    ''''''

    from yb.auxiliaries import get_management_key_for_write

    reader: str = ctx.obj['reader']
    management_key: str | None = get_management_key_for_write(ctx)
    pin: str | None = ctx.obj.get('pin')
    piv = ctx.obj['piv']

    # Call orchestrator
    try:
        success = orchestrator.remove_blob(
            reader=reader,
            piv=piv,
            name=name,
            management_key=management_key,
            pin=pin,
        )

        if not success:
            raise click.ClickException(f'Cannot find object {name}')

    except ValueError as e:
        raise click.ClickException(str(e)) from e
