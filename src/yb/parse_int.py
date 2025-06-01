import click

def parse_int_base_0(value):
    try:
        return int(value, 0)  # base 0 allows 0x..., 0o..., 0b..., or decimal
    except ValueError:
        raise click.BadParameter(f"Invalid number: {value!r}")
