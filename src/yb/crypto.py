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
            subject: str,
            pin: str | None = None,
            management_key: str | None = None,
            debug: bool = False,
        ) -> None:
        '''
        Generate an EC P-256 keypair in the given PIV slot using yubico-piv-tool.

        Parameters:
        - slot: PIV slot to generate key in
        - subject: X.509 subject for the certificate
        - pin: YubiKey PIN (optional, will prompt if not provided)
        - management_key: Management key (optional, will use default if not provided)
        - debug: Enable debug output
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
            cmd = [
                'yubico-piv-tool',
                '--reader', reader,
                '--action', 'generate',
                '--slot', slot,
                '--algorithm', 'ECCP256',
                '--touch-policy', 'never',
                '--pin-policy', 'once',
                '--output', pubkey_path,
            ]
            if management_key:
                cmd += [f'--key={management_key}']
                if debug:
                    print(f'[DEBUG] Crypto: Added --key to generate command', file=sys.stderr)
            else:
                if debug:
                    print(f'[DEBUG] Crypto: WARNING - No management_key provided!', file=sys.stderr)

            if debug:
                print(f'[DEBUG] Crypto: Full command ({len(cmd)} args):', file=sys.stderr)
                for i, arg in enumerate(cmd):
                    print(f'[DEBUG] Crypto:   [{i}] = {repr(arg)}', file=sys.stderr)

            result = subprocess.run(cmd, capture_output=True, text=True)

            if debug:
                print(f'[DEBUG] Crypto: yubico-piv-tool generate exit code: {result.returncode}', file=sys.stderr)
                if result.stdout:
                    print(f'[DEBUG] Crypto: generate stdout:', file=sys.stderr)
                    print(result.stdout, file=sys.stderr)
                if result.stderr:
                    print(f'[DEBUG] Crypto: generate stderr:', file=sys.stderr)
                    print(result.stderr, file=sys.stderr)

            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)

            # --- Generate self-signed certificate using public key

            cmd = [
                'yubico-piv-tool',
                '--reader', reader,
                '--action', 'verify-pin',
                '--slot', slot,
                '--subject', subject,
                '--action', 'selfsign',
                '--input', pubkey_path,
                '--output', cert_path,
            ]
            if pin:
                cmd += ['--pin', pin]
            if management_key:
                cmd += [f'--key={management_key}']
                if debug:
                    print(f'[DEBUG] Crypto: Added --key to selfsign command', file=sys.stderr)
            else:
                if debug:
                    print(f'[DEBUG] Crypto: WARNING - No management_key for selfsign!', file=sys.stderr)

            if debug:
                print(f'[DEBUG] Crypto: Running yubico-piv-tool selfsign', file=sys.stderr)
                print(f'[DEBUG] Crypto: Full command ({len(cmd)} args):', file=sys.stderr)
                for i, arg in enumerate(cmd):
                    print(f'[DEBUG] Crypto:   [{i}] = {repr(arg)}', file=sys.stderr)

            result = subprocess.run(cmd, capture_output=True, text=True)

            if debug:
                print(f'[DEBUG] Crypto: yubico-piv-tool selfsign exit code: {result.returncode}', file=sys.stderr)
                if result.stdout:
                    print(f'[DEBUG] Crypto: selfsign stdout:', file=sys.stderr)
                    print(result.stdout, file=sys.stderr)
                if result.stderr:
                    print(f'[DEBUG] Crypto: selfsign stderr:', file=sys.stderr)
                    print(result.stderr, file=sys.stderr)

            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)

            # --- Import certificate into the Yubikey

            cmd = [
                'yubico-piv-tool',
                '--reader', reader,
                '--action', 'import-certificate',
                '--slot', slot,
                '--input', cert_path,
            ]
            if management_key:
                cmd += [f'--key={management_key}']
                if debug:
                    print(f'[DEBUG] Crypto: Added --key to import-certificate command', file=sys.stderr)
            else:
                if debug:
                    print(f'[DEBUG] Crypto: WARNING - No management_key for import-certificate!', file=sys.stderr)

            if debug:
                print(f'[DEBUG] Crypto: Running yubico-piv-tool import-certificate', file=sys.stderr)
                print(f'[DEBUG] Crypto: Full command ({len(cmd)} args):', file=sys.stderr)
                for i, arg in enumerate(cmd):
                    print(f'[DEBUG] Crypto:   [{i}] = {repr(arg)}', file=sys.stderr)

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if debug:
                print(f'[DEBUG] Crypto: yubico-piv-tool import-certificate exit code: {result.returncode}', file=sys.stderr)
                if result.stdout:
                    print(f'[DEBUG] Crypto: import-certificate stdout:', file=sys.stderr)
                    print(result.stdout, file=sys.stderr)
                if result.stderr:
                    print(f'[DEBUG] Crypto: import-certificate stderr:', file=sys.stderr)
                    print(result.stderr, file=sys.stderr)

            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)


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
            serial: int,
            slot: str,
            encrypted_blob: bytes,
            pin: str | None = None,
            debug: bool = False,
        ) -> bytes:
        '''
        Decrypts the encrypted blob which consists of:
        ephemeral_pubkey (65 bytes for uncompressed point on P-256) + IV (16 bytes) + ciphertext.
        Uses YubiKey ECDH private key operation to derive shared secret.

        Args:
            serial: YubiKey serial number (used to select correct token for ECDH)
            slot: PIV slot containing the private key (e.g., '9e')
            encrypted_blob: Concatenated ephemeral_pubkey + IV + ciphertext
            pin: Optional PIN for PKCS#11 login
            debug: Enable verbose debugging output

        Returns:
            Decrypted plaintext bytes
        '''
        # Constants
        CURVE = ec.SECP256R1()
        PUB_KEY_LEN = 65  # Uncompressed SECP256R1 point (0x04 + 32-byte X + 32-byte Y)
        IV_LEN = 16

        if debug:
            print(f'[DEBUG] hybrid_decrypt: encrypted_blob length = {len(encrypted_blob)}',
                  file=sys.stderr)

        # Slice encrypted blob
        ephemeral_pub = encrypted_blob[:PUB_KEY_LEN]
        iv = encrypted_blob[PUB_KEY_LEN : PUB_KEY_LEN + IV_LEN]
        ciphertext = encrypted_blob[PUB_KEY_LEN + IV_LEN :]

        if debug:
            print(f'[DEBUG] ephemeral_pub length = {len(ephemeral_pub)}', file=sys.stderr)
            print(f'[DEBUG] iv length = {len(iv)}', file=sys.stderr)
            print(f'[DEBUG] ciphertext length = {len(ciphertext)}', file=sys.stderr)
            print(f'[DEBUG] ephemeral_pub (hex) = {ephemeral_pub.hex()}', file=sys.stderr)
            print(f'[DEBUG] iv (hex) = {iv.hex()}', file=sys.stderr)

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

        if debug:
            print(f'[DEBUG] der_spki length = {len(der_spki)}', file=sys.stderr)
            print(f'[DEBUG] der_spki (hex) = {der_spki.hex()}', file=sys.stderr)

        # Derive shared secret via YubiKey
        shared_secret = Crypto.perform_ecdh_with_yubikey(
            serial, slot, der_spki, pin, debug)

        if debug:
            print(f'[DEBUG] shared_secret length = {len(shared_secret)}', file=sys.stderr)
            print(f'[DEBUG] shared_secret (hex) = {shared_secret.hex()}', file=sys.stderr)

        # Derive AES key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption',
            backend=default_backend(),
        ).derive(shared_secret)

        if debug:
            print(f'[DEBUG] derived_key (hex) = {derived_key.hex()}', file=sys.stderr)

        # Decrypt AES-CBC with PKCS7 unpadding
        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if debug:
            print(f'[DEBUG] padded_plaintext length = {len(padded_plaintext)}', file=sys.stderr)
            print(f'[DEBUG] padded_plaintext first 32 bytes (hex) = {padded_plaintext[:32].hex()}',
                  file=sys.stderr)
            print(f'[DEBUG] padded_plaintext last 32 bytes (hex) = {padded_plaintext[-32:].hex()}',
                  file=sys.stderr)

        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        if debug:
            print(f'[DEBUG] plaintext length after unpadding = {len(plaintext)}', file=sys.stderr)

        return plaintext


    # --- CRYPTO PERFORM_ECDH_WITH_YUBIKEY -------------------------------------

    @classmethod
    def perform_ecdh_with_yubikey(
            cls,
            serial: int,
            slot_label: str,
            encrypted_blob: bytes,
            pin: str | None = None,
            debug: bool = False,
        ) -> bytes:
        '''
        Perform ECDH key derivation using YubiKey private key via PKCS#11.

        Args:
            serial: YubiKey serial number (used to select correct PKCS#11 token)
            slot_label: PIV slot label (e.g., '82' for Key Management)
            encrypted_blob: DER-encoded SPKI public key for ECDH
            pin: Optional PIN for PKCS#11 login
            debug: Enable verbose debugging output

        Returns:
            ECDH-derived shared secret (32 bytes for P-256)
        '''
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

        # Construct PKCS#11 token label from serial number
        token_label = f"YubiKey PIV #{serial}"

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
                '--token-label', token_label,
                '-l',
                '--derive',
                '-m', 'ECDH1-DERIVE',
                '--id', id,
                '-i', ephemeral_pub_file.name,
                '-o', output_file.name,
            ]
            if pin is not None:
                cmd += [ '--pin', pin, ]

            if debug:
                # Import shutil only when debugging
                import shutil
                # Full instrumentation for troubleshooting
                print(f'[DEBUG] perform_ecdh: serial = {serial}', file=sys.stderr)
                print(f'[DEBUG] perform_ecdh: token_label = {token_label}', file=sys.stderr)
                print(f'[DEBUG] perform_ecdh: slot_label = {slot_label}', file=sys.stderr)
                print(f'[DEBUG] perform_ecdh: id = {id}', file=sys.stderr)
                print(f'[DEBUG] perform_ecdh: PKCS11_LIB = {PKCS11_LIB}', file=sys.stderr)
                pkcs11_tool_path = shutil.which('pkcs11-tool')
                print(f'[DEBUG] perform_ecdh: pkcs11-tool path = {pkcs11_tool_path}', file=sys.stderr)

                # Try to find the actual library file
                possible_lib_paths = [
                    PKCS11_LIB,
                    f'/usr/lib/{PKCS11_LIB}',
                    f'/usr/local/lib/{PKCS11_LIB}',
                ]
                if 'LD_LIBRARY_PATH' in os.environ:
                    for ld_path in os.environ['LD_LIBRARY_PATH'].split(':'):
                        possible_lib_paths.append(os.path.join(ld_path, PKCS11_LIB))

                resolved_lib = None
                for lib_path in possible_lib_paths:
                    if os.path.exists(lib_path):
                        resolved_lib = os.path.realpath(lib_path)
                        break

                print(f'[DEBUG] perform_ecdh: resolved libykcs11.so = {resolved_lib}', file=sys.stderr)

                # Get library version if possible
                if resolved_lib:
                    try:
                        import subprocess as sp
                        strings_out = sp.run(['strings', resolved_lib],
                                            capture_output=True, text=True, timeout=1)
                        for line in strings_out.stdout.split('\n'):
                            if 'yubico-piv-tool' in line.lower() or \
                               any(c.isdigit() and '.' in line for c in line[:20]):
                                if len(line) < 80 and len(line) > 3:
                                    print(f'[DEBUG] perform_ecdh: lib version hint: {line.strip()}',
                                          file=sys.stderr)
                                    break
                    except:
                        pass

                print(f'[DEBUG] perform_ecdh: cmd = {" ".join(cmd[:9])}...', file=sys.stderr)

            # Run the pkcs11-tool subprocess
            subprocess.run(cmd, capture_output=True)

            # Read derived shared secret bytes from output file
            output_file.seek(0)
            shared_secret = output_file.read()

        return shared_secret
