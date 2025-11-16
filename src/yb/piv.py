# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod


class EjectionError(Exception):
    """Raised when a simulated YubiKey ejection occurs during a write operation."""
    pass


class PivInterface(ABC):
    """
    Abstract interface for PIV device operations.

    Concrete implementations:
    - HardwarePiv: Real YubiKey hardware via yubico-piv-tool and ykman
    - EmulatedPiv: In-memory emulation for testing
    """

    @abstractmethod
    def list_readers(self) -> list[str]:
        """
        Return a list of connected PIV reader names.
        """
        pass

    @abstractmethod
    def list_devices(self) -> list[tuple[int, str, str]]:
        """
        Return a list of connected YubiKeys with their serial numbers.

        Returns:
            List of tuples (serial, version, reader) for each connected YubiKey.
            - serial: YubiKey serial number (int)
            - version: YubiKey version string (e.g., "5.7.1")
            - reader: PC/SC reader name

        Raises:
            RuntimeError: If device enumeration fails.
        """
        pass

    @abstractmethod
    def get_reader_for_serial(self, serial: int) -> str:
        """
        Get the PC/SC reader name for a YubiKey with the given serial number.

        Parameters:
            serial: YubiKey serial number to find

        Returns:
            PC/SC reader name for the YubiKey with the given serial

        Raises:
            ValueError: If no YubiKey with the given serial is found
            RuntimeError: If enumeration fails
        """
        pass

    @abstractmethod
    def write_object(
        self,
        reader: str,
        id: int,
        input: bytes,
        management_key: str | None = None,
    ) -> None:
        """
        Write binary data to a PIV object slot on the device.

        Parameters:
        - reader: The name of the reader to use.
        - id: The numeric ID of the PIV object (e.g. 0x5fc105).
        - input: The binary content to write.
        - management_key: Optional 48-char hex management key.

        Raises:
        - RuntimeError: If the write operation fails.
        """
        pass

    @abstractmethod
    def read_object(self, reader: str, id: int) -> bytes:
        """
        Read binary data from a PIV object slot on the device.

        Parameters:
        - reader: The name of the reader to use.
        - id: The numeric ID of the PIV object (e.g. 0x5fc105).

        Returns:
        - The binary content read from the PIV object.

        Raises:
        - RuntimeError: If the read operation fails.
        """
        pass

    @abstractmethod
    def verify_reader(self, reader: str, id: int) -> bool:
        """
        Verify reader by attempting PIN verification.

        Parameters:
        - reader: The name of the reader to verify.
        - id: The numeric ID for verification.

        Returns:
        - True if verification succeeds, False otherwise.
        """
        pass


class HardwarePiv(PivInterface):
    """
    Hardware implementation of PIV operations using real YubiKey devices.

    Uses yubico-piv-tool and ykman for device communication.
    """

    def list_readers(self) -> list[str]:
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

    def list_devices(self) -> list[tuple[int, str, str]]:
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

    def get_reader_for_serial(self, serial: int) -> str:
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
        devices = self.list_devices()

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

    def write_object(
        self,
        reader: str,
        id: int,
        input: bytes,
        management_key: str | None = None,
    ) -> None:
        """
        Write binary data to a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).
        - input: The binary content to write.
        - management_key: Optional 48-char hex management key. If None, uses YubiKey default.

        Raises:
        - RuntimeError: If the command fails or the write operation is unsuccessful.
        """

        cmd = [
            'yubico-piv-tool',
            '--reader', reader,
        ]

        # Add management key if provided
        if management_key is not None:
            cmd.extend(['--key', management_key])

        cmd.extend([
            '--action', 'write-object',
            '--format', 'binary',
            '--id', f'{id:#06x}',
        ])

        try:
            subprocess.run(
                cmd,
                input=input,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip()
            # Provide helpful error message if authentication failed
            if 'authentication' in error_msg.lower() or 'verify' in error_msg.lower():
                raise RuntimeError(
                    f"Failed to write object: {error_msg}\n"
                    "Hint: If using a non-default management key, specify it with --key"
                ) from e
            raise RuntimeError(f"Failed to write object: {error_msg}") from e


    def read_object(self, reader: str, id: int) -> bytes:
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
        
    def verify_reader(self, reader: str, id: int) -> bool:
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


class EmulatedPiv(PivInterface):
    """
    In-memory emulation of PIV operations for testing.

    Does not require physical YubiKey hardware. All operations are performed
    on in-memory data structures.
    """

    class EmulatedDevice:
        """Represents a single emulated YubiKey device."""

        def __init__(self, serial: int, version: str):
            self.serial = serial
            self.version = version
            self.reader = f"Emulated YubiKey {serial}"
            # PIV object storage: object_id -> bytes
            self.objects: dict[int, bytes] = {}

    def __init__(self, ejection_probability: float = 0.0, seed: int | None = None):
        """
        Initialize empty emulated PIV environment.

        Args:
            ejection_probability: Probability (0.0-1.0) of ejection during write (default: 0.0)
            seed: Random seed for deterministic ejection simulation (default: None for random)
        """
        # Map serial -> EmulatedDevice
        self._devices: dict[int, EmulatedPiv.EmulatedDevice] = {}

        # Ejection simulation
        self.ejection_probability = ejection_probability
        self.ejection_count = 0
        self.write_count = 0
        self.is_ejected = False

        # Random number generator for ejection simulation
        if seed is not None:
            import random
            self._rng = random.Random(seed)
        else:
            import random
            self._rng = random.Random()

    def reconnect(self) -> None:
        """
        Reconnect the emulated device after ejection.

        This simulates plugging the YubiKey back in after physical removal.
        """
        self.is_ejected = False

    def add_device(self, serial: int, version: str = "5.7.1") -> str:
        """
        Add an emulated YubiKey device.

        Parameters:
            serial: YubiKey serial number
            version: YubiKey firmware version (default: "5.7.1")

        Returns:
            Reader name for the newly added device
        """
        device = EmulatedPiv.EmulatedDevice(serial, version)
        self._devices[serial] = device
        return device.reader

    def list_readers(self) -> list[str]:
        """Return list of emulated reader names."""
        return [device.reader for device in self._devices.values()]

    def list_devices(self) -> list[tuple[int, str, str]]:
        """Return list of (serial, version, reader) for all emulated devices."""
        return [
            (device.serial, device.version, device.reader)
            for device in self._devices.values()
        ]

    def get_reader_for_serial(self, serial: int) -> str:
        """Get reader name for a specific serial number."""
        if serial not in self._devices:
            available = [str(s) for s in self._devices.keys()]
            if not available:
                raise ValueError("No YubiKeys found")
            raise ValueError(
                f"No YubiKey found with serial {serial}. "
                f"Available: {', '.join(available)}"
            )
        return self._devices[serial].reader

    def _get_device_by_reader(self, reader: str) -> EmulatedDevice:
        """Internal helper to get device by reader name."""
        for device in self._devices.values():
            if device.reader == reader:
                return device
        raise RuntimeError(f"Reader not found: {reader}")

    def write_object(
        self,
        reader: str,
        id: int,
        input: bytes,
        management_key: str | None = None,
    ) -> None:
        """
        Write object to emulated device storage.

        May raise EjectionError if ejection simulation is enabled and triggered.
        """
        # Check if device is already ejected
        if self.is_ejected:
            raise RuntimeError(f"Device ejected: {reader}")

        # Simulate ejection before write
        if self.ejection_probability > 0:
            self.write_count += 1
            if self._rng.random() < self.ejection_probability:
                self.ejection_count += 1
                self.is_ejected = True
                raise EjectionError(
                    f"Simulated ejection during write to object {id:#06x} "
                    f"(ejection #{self.ejection_count}, write #{self.write_count})"
                )

        # Perform the write
        device = self._get_device_by_reader(reader)
        device.objects[id] = input

    def read_object(self, reader: str, id: int) -> bytes:
        """Read object from emulated device storage."""
        device = self._get_device_by_reader(reader)
        if id not in device.objects:
            raise RuntimeError(f"Object {id:#06x} not found on device")
        return device.objects[id]

    def verify_reader(self, reader: str, id: int) -> bool:
        """Always returns True for emulated devices (no PIN required)."""
        # Just verify the reader exists
        try:
            self._get_device_by_reader(reader)
            return True
        except RuntimeError:
            return False
