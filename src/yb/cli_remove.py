# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click

from yb import orchestrator


# === REMOVE ===================================================================


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
