# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import subprocess

class Piv:
    """
    Represents operations related to a PIV device functionality.
    """

    @classmethod
    def list_readers(
            cls,
        ) -> list[str]:
        """
        Return a list of connected PIV reader names.
        """

        try:
            out = subprocess.run(
                [
                    'yubico-piv-tool',
                    '--action', 'list-readers'
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to list readers: {e.stderr.strip()}") from e

        readers = []
        for line in out.stdout.splitlines():
            readers.append(line.strip())
        return readers

    @classmethod
    def list_devices(cls) -> list[tuple[int, str, str]]:
        """
        Return a list of connected YubiKeys with their serial numbers.

        Returns:
            List of tuples (serial, version, reader) for each connected YubiKey.
            - serial: YubiKey serial number (int)
            - version: YubiKey version string (e.g., "5.7.1")
            - reader: PC/SC reader name

        Raises:
            RuntimeError: If ykman is not available or device enumeration fails.
        """
        try:
            from ykman.device import list_all_devices
        except ImportError as e:
            raise RuntimeError(
                "ykman library not available. "
                "Install yubikey-manager: pip install yubikey-manager"
            ) from e

        try:
            devices = list(list_all_devices())
        except Exception as e:
            raise RuntimeError(f"Failed to enumerate YubiKeys: {e}") from e

        result = []
        for device, info in devices:
            serial = info.serial
            version = str(info.version)
            reader = device.fingerprint  # PC/SC reader name

            result.append((serial, version, reader))

        return result

    @classmethod
    def get_reader_for_serial(cls, serial: int) -> str:
        """
        Get the PC/SC reader name for a YubiKey with the given serial number.

        Parameters:
            serial: YubiKey serial number to find

        Returns:
            PC/SC reader name for the YubiKey with the given serial

        Raises:
            ValueError: If no YubiKey with the given serial is found
            RuntimeError: If ykman is not available or enumeration fails
        """
        devices = cls.list_devices()

        for dev_serial, _, reader in devices:
            if dev_serial == serial:
                return reader

        # Build helpful error message
        if not devices:
            raise ValueError("No YubiKeys found")

        available_serials = [str(s) for s, _, _ in devices]
        raise ValueError(
            f"No YubiKey found with serial {serial}. "
            f"Available: {', '.join(available_serials)}"
        )

    @classmethod
    def write_object(
            cls,
            reader: str,
            id: int,
            input: bytes,
        ) -> None:
        """
        Write binary data to a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).
        - input: The binary content to write.

        Raises:
        - RuntimeError: If the command fails or the write operation is unsuccessful.
        """
        
        try:
            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'write-object',
                    '--format', 'binary',
                    '--id', f'{id:#06x}',
                ],
                input=input,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to write object: {e.stderr.decode().strip()}") from e


    @classmethod
    def read_object(
            cls,
            reader: str,
            id: int,
        ) -> bytes:
        """
        Read binary data from a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).

        Returns:
        - The binary content read from the PIV object.

        Raises:
        - RuntimeError: If the command fails or the read operation is unsuccessful.
        """
        try:
            out = subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'read-object',
                    '--format', 'binary',
                    '--id', f'{id:#06x}',
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return out.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to read object: {e.stderr.decode().strip()}") from e
        
    @classmethod
    def verify_reader(
            cls,
            reader: str,
            id: int,
        ) -> bool:
        ''''''
        try:
            with open("/dev/null", "rb") as devnull:
                subprocess.run(
                    [
                        'yubico-piv-tool',
                        '--reader', reader,
                        '--action', 'verify-pin',
                        '--id', f'{id:#06x}',
                    ],
                    stdin=devnull,
                    capture_output=True,
                    text=True,
                    check=True,
                )
        except subprocess.CalledProcessError:
            return False
        return True
