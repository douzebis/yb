# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
import yaml
from yb.piv import HardwarePiv

# === LIST-READERS =============================================================


@click.command(
    "list-readers",
    help="""
    List all available YubiKey PIV readers connected to the system.
    """,
)
@click.pass_context
def cli_list_readers(ctx) -> None:
    piv = ctx.obj.get('piv') if ctx.obj else HardwarePiv()
    readers = piv.list_readers()
    print(yaml.dump(readers))
