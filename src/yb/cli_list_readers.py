# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import click
import yaml
from yb.piv import Piv

# === LIST-READERS =============================================================


@click.command(
    "list-readers",
    help="""
    List all available YubiKey PIV readers connected to the system.
    """,
)
def cli_list_readers() -> None:
    readers = Piv.list_readers()
    print(yaml.dump(readers))
