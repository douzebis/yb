# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations
import sys
from datetime import datetime
import click

def format_timestamp(ts: int) -> str:
    dt = datetime.fromtimestamp(ts)  # convert to local datetime
    return dt.strftime('%c')  # locale-appropriate datetime string


def verify_device_if_needed(ctx):
    """
    Verify device PIN for write operations (unless -x flag was specified).

    This should be called by write commands (format, store, remove) at the
    beginning of their execution to confirm user identity before making changes.

    Read-only commands (ls, fetch, fsck) should NOT call this.

    Args:
        ctx: Click context containing 'piv', 'reader', 'pin', and 'no_verify' in ctx.obj

    Raises:
        click.ClickException: If PIN verification fails
    """
    if ctx.obj.get('no_verify', False):
        return  # -x flag was specified, skip verification

    reader = ctx.obj['reader']
    piv = ctx.obj['piv']
    pin = ctx.obj.get('pin')

    if pin is None:
        print('Confirm by entering your PIN...', file=sys.stderr)

    if not piv.verify_reader(reader, 0x9a, pin=pin):
        raise click.ClickException('Could not verify the PIN.')


class StringTooLargeError(ValueError):
    pass
