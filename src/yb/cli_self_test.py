#!/usr/bin/env python
# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Self-test command for yb.

Runs comprehensive end-to-end testing on a real YubiKey.
"""

import sys

import click

from yb.self_test import run_self_test


@click.command(name='self-test')
@click.option(
    '-n', '--count',
    type=int,
    default=200,
    show_default=True,
    help='Number of test operations to perform'
)
@click.pass_context
def cli_self_test(ctx, count: int) -> None:
    """
    Run end-to-end self-test on the selected YubiKey.

    WARNING: This will FORMAT the YubiKey and DESTROY ALL BLOB DATA!

    The self-test performs random operations (store/fetch/remove/list)
    to verify correct CLI functionality. Both encrypted and unencrypted
    blobs are tested.

    Requires --serial to specify which YubiKey to test.

    Example:
        yb --serial 12345678 self-test

        yb --serial 12345678 --pin 123456 --key 010203...0708 self-test -n 100
    """
    if count < 1:
        raise click.BadParameter('count must be at least 1')

    # Get context values
    reader = ctx.obj.get('reader')
    pin = ctx.obj.get('pin')
    mgmt_key = ctx.obj.get('management_key')
    debug = ctx.obj.get('debug', False)
    piv = ctx.obj.get('piv')

    # Check if --serial was explicitly provided
    # We need to check the parent context for the serial parameter
    serial_provided = ctx.parent.params.get('serial') is not None

    if not serial_provided:
        raise click.ClickException(
            'self-test requires --serial to be explicitly specified.\n\n'
            'Example: yb --serial 12345678 self-test'
        )

    # Get serial number from reader
    # We need the serial, not the reader name
    try:
        devices = piv.list_devices()

        # Find serial for this reader
        serial = None
        for dev_serial, _, dev_reader in devices:
            if dev_reader == reader:
                serial = dev_serial
                break

        if serial is None:
            raise click.ClickException(
                'Could not determine serial number for selected YubiKey.'
            )
    except Exception as e:
        raise click.ClickException(
            f'Failed to get YubiKey serial number: {e}'
        )

    # Run self-test and exit with its status code
    exit_code = run_self_test(
        serial=serial,
        pin=pin,
        mgmt_key=mgmt_key,
        num_operations=count,
        debug=debug
    )
    sys.exit(exit_code)
