
import click
from yb.store import Store, Object
from yb.x509_subject import verify_x509_subject
from yb.crypto import Crypto

from yb.constants import (
    DEFAULT_OBJECT_COUNT,
    DEFAULT_X509_SUBJECT,
    MAX_OBJECT_COUNT,
    MIN_OBJECT_COUNT,
    OBJECT_MAX_SIZE,
    OBJECT_MIN_SIZE,
    YBLOB_MAGIC,
)

from yb.parse_int import parse_int_base_0

# === FORMAT ===================================================================


@click.command(
    'format',
    help='''
    Initialize a YubiKey slot with an ECC P-256 (secp256r1) key pair for use in blob encryption/decryption.

    This key will be used to derive shared secrets using ECDH.
    ''',
)
@click.option(
    '-c', '--object-count',
    type=str,
    callback=lambda ctx, param, value: parse_int_base_0(value),
    default=DEFAULT_OBJECT_COUNT,
    show_default=True,
    help="Count of PIV objects to use for storage.",
)
@click.option(
    '-s', '--object-size',
    type=str,
    callback=lambda ctx, param, value: parse_int_base_0(value),
    default=OBJECT_MAX_SIZE,
    show_default=True,
    help='Size to use for the PIV objects.',
)
@click.option(
    '-k', '--key-slot',
    type=str,
    default='82',
    show_default=True,
    help='YubiKey slot ID to generate the key pair.',
)
@click.option(
    '-g', '--generate/--no-generate',
    is_flag=True,
    default=False,
    show_default=True,
    help='',
)
@click.option(
    '-n', '--subject',
    type=str,
    default=DEFAULT_X509_SUBJECT,
    show_default=False,
    help='',
)
@click.pass_context
def cli_format(ctx,
    object_size: int,
    object_count: int,
    key_slot: str,
    generate: bool,
    subject: str,
) -> None:
    'Format a PIV device for storing binary blobs.'''

    # --- Check options sanity -------------------------------------------------

    if object_size < OBJECT_MIN_SIZE:
        raise click.BadParameter(f'object-size cannot be lower than {OBJECT_MIN_SIZE}')
    if object_size > OBJECT_MAX_SIZE:
        raise click.BadParameter(f'object-size cannot greater than {OBJECT_MAX_SIZE}')
    if object_count < MIN_OBJECT_COUNT:
        raise click.BadParameter(
            f'object-count cannot be lower than {MIN_OBJECT_COUNT}'
        )
    if object_count > MAX_OBJECT_COUNT:
        raise click.BadParameter(f'object-count cannot greater than {MAX_OBJECT_COUNT}')
    if key_slot not in {'9a', '9c', '9d', '9e', '82', '83', '84', '85', '86',
                        '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
                        '90', '91', '92', '93', '94', '95'}:
        raise click.BadParameter('key-slot must be 9a, 9c-9e, or 82-95')
    try:
        verify_x509_subject(subject)
    except ValueError as e:
        raise click.ClickException(f'Invalid subject: {e}')

    reader: str = ctx.obj['reader']

    # Provision or check the ECCP256 key
    if generate:
        Crypto.generate_certificate(
            reader=reader,
            slot=key_slot,
            subject=subject,
        )
    else:
        sub = Crypto.get_certificate_subject(
            reader=reader,
            slot=key_slot,
        )
        if sub != subject:
            raise click.ClickException(f'PIV slot {key_slot} has bad subject: {sub}')

    # Format the Store part
    store = Store(
        reader,
        yblob_magic=YBLOB_MAGIC,
        object_size_in_store=object_size,
        object_count_in_store=object_count,
        store_encryption_key_slot=int(f'0x{key_slot}', 0),
    )
    for index in range(object_count):
        obj = Object(
            store=store,
            object_index_in_store=index,
            object_age=0,
        )
        store.commit_object(obj)
    
    store.sync()