# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

import os
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

PKCS11_LIB = "libykcs11.so"


# === CRYPTO ===================================================================

class Crypto:

    # --- CRYPTO GENERATE_CERTIFICATE ------------------------------------------

    @classmethod
    def generate_certificate(
            cls,
            reader: str,
            slot: str,
            subject:str
        ) -> None:
        '''
        Generate an EC P-256 keypair in the given PIV slot using yubico-piv-tool.

        Parameters:
        - slot: PIV slot to generate key in
        '''
        subject += '/'

        with (
            tempfile.NamedTemporaryFile() as pubkey_file,
            tempfile.NamedTemporaryFile() as cert_file,
        ):
            pubkey_path = pubkey_file.name
            cert_path = cert_file.name

            # --- Generate ECCP256 keypair

            print(f'Generating EC P-256 keypair in slot {slot}...', file=sys.stderr)
            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'generate',
                    '--slot', slot,
                    '--algorithm', 'ECCP256',
                    '--touch-policy', 'never',
                    '--pin-policy', 'once',
                    '--output', pubkey_path,
                ],
                check=True,
            )

            # --- Generate self-signed certificate using public key

            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'verify-pin',
                    '--slot', slot,
                    '--subject', subject,
                    '--action', 'selfsign',
                    '--input', pubkey_path,
                    '--output', cert_path,
                ],
                check=True,
            )
            # --- Import certificate into the Yubikey

            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'import-certificate',
                    '--slot', slot,
                    '--input', cert_path,
                ],
                check=True,
            )


    # --- CRYPTO GET_CERTIFICATE_SUBJECT ---------------------------------------

    @classmethod
    def get_certificate_subject(
            cls,
            reader: str,
            slot: str,
        ) -> str:
        # Use tempfile to store the certificate temporarily
        with tempfile.NamedTemporaryFile() as cert_file:

            # Step 1: Run yubico-piv-tool to read the certificate and save it to the temp file
            with open(cert_file.name, 'wb') as f:
                subprocess.run(
                    [
                        'yubico-piv-tool',
                        '--reader', reader,
                        '--slot', slot,
                        '--action', 'read-certificate',
                    ],
                    stdout=f,
                    check=True,
                )

            # Step 2: Run openssl to extract the subject from the certificate file
            out = subprocess.run(
                [
                    'openssl',
                    'x509', '-noout', '-subject',
                    '-nameopt', 'compat',
                    '-in', cert_file.name,
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            # e.g. 'subject=/CN=foo/' -> '/CN=foo/'
            subject = out.stdout.strip()[8:]
            return subject


    # --- CRYPTO GET_PUBLIC_KEY_FROM_YUBIKEY -----------------------------------

    @classmethod
    def get_public_key_from_yubikey(
            cls,
            reader: str,
            slot: str
        ):
        '''
        Retrieves the certificate from the YubiKey slot using yubico-piv-tool,
        then parses it to extract the public key.

        Args:
            slot (str): The PIV slot identifier (e.g., '9e')

        Returns:
            public_key: cryptography public key object (e.g., EllipticCurvePublicKey)
        '''
        with tempfile.NamedTemporaryFile() as cert_file:
            cert_path = cert_file.name
            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--slot', slot,
                    '--action', 'read-certificate',
                    '--output', cert_path,
                ],
                check=True,
            )

            with open(cert_path, 'rb') as f:
                cert_pem = f.read()

        # Parse DER-encoded certificate using cryptography
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        pubkey = cert.public_key()

        return pubkey


    # --- CRYPTO HYBRID_ENCRYPT ------------------------------------------------

    @classmethod
    def hybrid_encrypt(
            cls,
            blob: bytes,
            peer_public_key
        ):
        # Generate ephemeral private key for ECDH
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Perform ECDH to get shared secret
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive AES key from shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption',
            backend=default_backend(),
        ).derive(shared_secret)

        # AES CBC encryption with PKCS7 padding
        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded_data = padder.update(blob) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_blob = encryptor.update(padded_data) + encryptor.finalize()

        # Serialize ephemeral public key to send along with ciphertext
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Return ephemeral public key + iv + ciphertext
        return ephemeral_pub_bytes + iv + encrypted_blob


    # --- CRYPTO HYBRID_DECRYPT ------------------------------------------------

    @classmethod
    def hybrid_decrypt(
            cls,
            reader: str,
            slot: str,
            encrypted_blob: bytes,
            pin: str | None = None,
        ) -> bytes:
        '''
        Decrypts the encrypted blob which consists of:
        ephemeral_pubkey (65 bytes for uncompressed point on P-256) + IV (16 bytes) + ciphertext.
        Uses YubiKey ECDH private key operation to derive shared secret.
        '''
        # Constants
        CURVE = ec.SECP256R1()
        PUB_KEY_LEN = 65  # Uncompressed SECP256R1 point (0x04 + 32-byte X + 32-byte Y)
        IV_LEN = 16

        # Slice encrypted blob
        ephemeral_pub = encrypted_blob[:PUB_KEY_LEN]
        iv = encrypted_blob[PUB_KEY_LEN : PUB_KEY_LEN + IV_LEN]
        ciphertext = encrypted_blob[PUB_KEY_LEN + IV_LEN :]

        # Extract x and y from public key
        x = int.from_bytes(ephemeral_pub[1:33], 'big')
        y = int.from_bytes(ephemeral_pub[33:], 'big')

        # Reconstruct public key and encode to SPKI DER
        public_key = ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key(
            default_backend()
        )
        der_spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Derive shared secret via YubiKey
        shared_secret = Crypto.perform_ecdh_with_yubikey(
            reader, slot, der_spki, pin)

        # Derive AES key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption',
            backend=default_backend(),
        ).derive(shared_secret)

        # Decrypt AES-CBC with PKCS7 unpadding
        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext


    # --- CRYPTO PERFORM_ECDH_WITH_YUBIKEY -------------------------------------

    @classmethod
    def perform_ecdh_with_yubikey(
            cls,
            reader: str,
            slot_label: str,
            encrypted_blob: bytes,
            pin: str | None = None,
        ) -> bytes:
        ids = {
            '9a': '01',
            '9c': '02',
            '9d': '03',
            '9e': '04',
            '82': '05',
            '83': '06',
            '84': '07',
            '85': '08',
            '86': '09',
            '87': '0a',
            '88': '0b',
            '89': '0c',
            '8a': '0d',
            '8b': '0e',
            '8c': '0f',
            '8d': '10',
            '8e': '11',
            '8f': '12',
            '90': '13',
            '91': '14',
            '92': '15',
            '93': '16',
            '94': '17',
            '95': '18',
        }
        id = ids[slot_label]

        # Write ephemeral public key bytes to a temp file (simulate input file for pkcs11-tool)
        with (
            tempfile.NamedTemporaryFile() as ephemeral_pub_file,
            tempfile.NamedTemporaryFile() as output_file,
        ):
            ephemeral_pub_file.write(encrypted_blob)
            ephemeral_pub_file.flush()

            cmd = [
                'pkcs11-tool',
                '--module', PKCS11_LIB,
                '-l',
                '--derive',
                '-m', 'ECDH1-DERIVE',
                '--id', id,
                '-i', ephemeral_pub_file.name,
                '-o', output_file.name,
            ]
            if pin is not None:
                cmd += [ '--pin', pin, ]

            # Run the pkcs11-tool subprocess
            subprocess.run(cmd, capture_output=True)

            # Read derived shared secret bytes from output file
            output_file.seek(0)
            shared_secret = output_file.read()

        return shared_secret
