# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from typing import Hashable


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
    def list_devices(self) -> list[tuple[int | None, str, Hashable]]:
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
    def get_reader_for_serial(self, serial: int) -> Hashable:
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
    def get_serial_for_reader(self, reader: Hashable) -> int:
        """
        Get the serial number for a YubiKey with the given PC/SC reader name.

        Parameters:
            reader: PC/SC reader name to find

        Returns:
            Serial number of the YubiKey

        Raises:
            ValueError: If no YubiKey with the given reader name is found
            RuntimeError: If enumeration fails
        """
        pass

    @abstractmethod
    def write_object(
        self,
        reader: Hashable,
        id: int,
        input: bytes,
        management_key: str | None = None,
        pin: str | None = None,
    ) -> None:
        """
        Write binary data to a PIV object slot on the device.

        Parameters:
        - reader: The name of the reader to use.
        - id: The numeric ID of the PIV object (e.g. 0x5fc105).
        - input: The binary content to write.
        - management_key: Optional 48-char hex management key.
        - pin: Optional PIN for PIN-protected management key mode.

        Raises:
        - RuntimeError: If the write operation fails.
        """
        pass

    @abstractmethod
    def read_object(self, reader: Hashable, id: int) -> bytes:
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
    def verify_reader(self, reader: Hashable, id: int, pin: str | None = None) -> bool:
        """
        Verify reader by attempting PIN verification.

        Parameters:
        - reader: The name of the reader to verify.
        - id: The numeric ID for verification.
        - pin: YubiKey PIN (optional, will prompt if not provided).

        Returns:
        - True if verification succeeds, False otherwise.
        """
        pass

    @abstractmethod
    def send_apdu(
        self,
        reader: Hashable,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b''
    ) -> bytes:
        """
        Send raw APDU command to PIV application and return response.

        Parameters:
        - reader: The name of the reader to use.
        - cla: Class byte of the APDU.
        - ins: Instruction byte of the APDU.
        - p1: Parameter 1 byte of the APDU.
        - p2: Parameter 2 byte of the APDU.
        - data: Optional data payload (default: empty).

        Returns:
        - Response data bytes (without status bytes).

        Raises:
        - RuntimeError: If APDU transmission fails or returns error status.
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

    def list_devices(self) -> list[tuple[int | None, str, Hashable]]:
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
            devices = list_all_devices()
        except Exception as e:
            raise RuntimeError(f"Failed to enumerate YubiKeys: {e}") from e

        result: list[tuple[int | None, str, Hashable]] = []
        for device, info in devices:
            serial = info.serial
            version = str(info.version)
            reader = device.fingerprint  # PC/SC reader name

            result.append((serial, version, reader))

        return result

    def get_reader_for_serial(self, serial: int) -> Hashable:
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

    def get_serial_for_reader(self, reader: Hashable) -> int:
        """
        Get the serial number for a YubiKey with the given PC/SC reader name.

        Parameters:
            reader: PC/SC reader name to find

        Returns:
            Serial number of the YubiKey

        Raises:
            ValueError: If no YubiKey with the given reader name is found
            RuntimeError: If ykman is not available or enumeration fails
        """
        devices = self.list_devices()

        for serial, _, dev_reader in devices:
            if dev_reader == reader:
                if serial is None:
                    raise ValueError(
                        f"YubiKey at reader '{reader}' has no serial number"
                    )
                return serial

        # Build helpful error message
        if not devices:
            raise ValueError("No YubiKeys found")

        available_readers = [str(r) for _, _, r in devices]
        raise ValueError(
            f"No YubiKey found with reader '{reader}'. "
            f"Available: {', '.join(available_readers)}"
        )

    def write_object(
        self,
        reader: Hashable,
        id: int,
        input: bytes,
        management_key: str | None = None,
        pin: str | None = None,
    ) -> None:
        """
        Write binary data to a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).
        - input: The binary content to write.
        - management_key: Optional 48-char hex management key. If None, uses YubiKey default.
        - pin: Optional PIN for PIN-protected management key mode.

        Raises:
        - RuntimeError: If the command fails or the write operation is unsuccessful.
        """


        cmd = [
            'yubico-piv-tool',
            '--reader', str(reader),
        ]

        # Add management key if provided
        if management_key is not None:
            cmd.append(f'--key={management_key}')

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

    def read_object(self, reader: Hashable, id: int) -> bytes:
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
                    '--reader', str(reader),
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
        
    def verify_reader(self, reader: Hashable, id: int, pin: str | None = None) -> bool:
        '''Verify reader by attempting PIN verification.'''
        try:
            cmd = [
                'yubico-piv-tool',
                '--reader', str(reader),
                '--action', 'verify-pin',
                '--id', f'{id:#06x}',
            ]
            if pin:
                cmd += ['--pin', pin]

            with open("/dev/null", "rb") as devnull:
                subprocess.run(
                    cmd,
                    stdin=devnull,
                    capture_output=True,
                    text=True,
                    check=True,
                )
        except subprocess.CalledProcessError:
            return False
        return True

    def send_apdu(
        self,
        reader: Hashable,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b''
    ) -> bytes:
        """
        Send raw APDU command to YubiKey using pyscard library.

        Implementation uses pyscard for direct smartcard communication.
        Falls back with helpful error if pyscard is not installed.

        Automatically selects the PIV applet before sending the command.

        Parameters:
        - reader: PC/SC reader name
        - cla: Class byte
        - ins: Instruction byte
        - p1: Parameter 1
        - p2: Parameter 2
        - data: Optional command data

        Returns:
        - Response data (without SW1/SW2 status bytes)

        Raises:
        - RuntimeError: If pyscard unavailable, reader not found, or APDU fails
        """
        try:
            from smartcard.System import readers
        except ImportError as e:
            raise RuntimeError(
                "pyscard library required for APDU commands. "
                "Install with: pip install pyscard"
            ) from e

        try:
            # Find the reader
            reader_list = readers()
            card_reader = None
            for r in reader_list:
                if str(reader) in str(r):
                    card_reader = r
                    break

            if not card_reader:
                raise RuntimeError(f"Reader not found: {reader}")

            # Connect to card
            connection = card_reader.createConnection()
            connection.connect()

            # Select PIV applet first (AID: A0 00 00 03 08)
            # This is required before sending any PIV-specific commands
            select_apdu = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08]
            response, sw1, sw2 = connection.transmit(select_apdu)

            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(f"Failed to select PIV applet: SW={sw1:02X}{sw2:02X}")

            # Build the actual APDU
            if data:
                apdu = [cla, ins, p1, p2, len(data)] + list(data)
            else:
                apdu = [cla, ins, p1, p2, 0]  # Le=0 means expect up to 256 bytes

            # Send APDU
            response, sw1, sw2 = connection.transmit(apdu)

            # Check status
            if sw1 != 0x90 or sw2 != 0x00:
                raise RuntimeError(f"APDU failed: SW={sw1:02X}{sw2:02X}")

            return bytes(response)

        except ImportError:
            raise  # Re-raise ImportError as-is (already has helpful message)
        except Exception as e:
            raise RuntimeError(f"APDU transmission failed: {e}") from e


class EmulatedPiv(PivInterface):
    """
    In-memory emulation of PIV operations for testing.

    Does not require physical YubiKey hardware. All operations are performed
    on in-memory data structures.
    """

    class EmulatedDevice:
        """Represents a single emulated YubiKey device."""

        def __init__(self, serial: int, version: str, pin_protected: bool = False):
            self.serial = serial
            self.version = version
            self.reader = f"Emulated YubiKey {serial}"
            # PIV object storage: object_id -> bytes
            self.objects: dict[int, bytes] = {}
            # Configuration flags
            self.pin_protected = pin_protected  # Whether PIN-protected mode is enabled

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

    def add_device(self, serial: int, version: str = "5.7.1", pin_protected: bool = False) -> str:
        """
        Add an emulated YubiKey device.

        Parameters:
            serial: YubiKey serial number
            version: YubiKey firmware version (default: "5.7.1")
            pin_protected: Whether to emulate PIN-protected management key mode (default: False)

        Returns:
            Reader name for the newly added device
        """
        device = EmulatedPiv.EmulatedDevice(serial, version, pin_protected)
        self._devices[serial] = device

        # If PIN-protected mode, automatically create ADMIN DATA and PRINTED objects
        if pin_protected:
            # Create ADMIN DATA object indicating PIN-protected mode
            # Format: 80 03 81 01 <bitfield>
            # Bitfield: 0x01 = 3DES PIN-protected, 0x02 = AES PIN-protected
            # Use 0x02 to simulate AES PIN-protected mode (like real YubiKeys with --protect)
            admin_data = bytes([0x80, 0x03, 0x81, 0x01, 0x02])
            device.objects[0x5FFF00] = admin_data

            # Create PRINTED object with a test management key
            # Format: 53 len 88 18 <24-byte key>
            # Using a fixed test key for emulation
            test_mgmt_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718')
            printed_data = bytes([0x53, 0x1A, 0x88, 0x18]) + test_mgmt_key
            device.objects[0x5FC109] = printed_data

        return device.reader

    def list_readers(self) -> list[str]:
        """Return list of emulated reader names."""
        return [device.reader for device in self._devices.values()]

    def list_devices(self) -> list[tuple[int | None, str, Hashable]]:
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

    def get_serial_for_reader(self, reader: Hashable) -> int:
        """Get serial number for a specific reader name."""
        for serial, device in self._devices.items():
            if device.reader == reader:
                return serial

        # Build helpful error message
        if not self._devices:
            raise ValueError("No YubiKeys found")

        available_readers = [device.reader for device in self._devices.values()]
        raise ValueError(
            f"No YubiKey found with reader '{reader}'. "
            f"Available: {', '.join(available_readers)}"
        )

    def _get_device_by_reader(self, reader: Hashable) -> EmulatedDevice:
        """Internal helper to get device by reader name."""
        for device in self._devices.values():
            if device.reader == reader:
                return device
        raise RuntimeError(f"Reader not found: {reader}")

    def write_object(
        self,
        reader: Hashable,
        id: int,
        input: bytes,
        management_key: str | None = None,
        pin: str | None = None,
    ) -> None:
        """
        Write object to emulated device storage.

        May raise EjectionError if ejection simulation is enabled and triggered.
        Pin parameter is ignored in emulation (no authentication required).
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

    def read_object(self, reader: Hashable, id: int) -> bytes:
        """Read object from emulated device storage."""
        device = self._get_device_by_reader(reader)
        if id not in device.objects:
            raise RuntimeError(f"Object {id:#06x} not found on device")
        return device.objects[id]

    def verify_reader(self, reader: Hashable, id: int, pin: str | None = None) -> bool:
        """Always returns True for emulated devices (no PIN required)."""
        # Just verify the reader exists (ignore PIN for emulated devices)
        try:
            self._get_device_by_reader(reader)
            return True
        except RuntimeError:
            return False

    def send_apdu(
        self,
        reader: Hashable,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b''
    ) -> bytes:
        """
        Emulate APDU responses for testing.

        Supports GET_METADATA (INS 0xF7) for testing default credential detection.
        Other APDUs are not implemented in emulation.

        Parameters:
        - reader: Reader name (must exist in emulated devices)
        - cla: Class byte
        - ins: Instruction byte
        - p1: Parameter 1
        - p2: Parameter 2
        - data: Command data (unused in current implementation)

        Returns:
        - Emulated response data

        Raises:
        - RuntimeError: If reader not found or APDU not supported
        """
        # Verify reader exists and get device
        device = self._get_device_by_reader(reader)

        # GET_METADATA command (INS 0xF7)
        if ins == 0xF7:
            # Return mock metadata based on slot (P2)
            # If device is PIN-protected, credentials should NOT be default

            if p2 == 0x80:  # PIN metadata
                if device.pin_protected:
                    # PIN is NOT default (changed), 3 total retries, 3 remaining
                    # Tag 0x05: is_default = 0x00 (NOT default)
                    # Tag 0x06: retries = 0x03 0x03 (total=3, remaining=3)
                    return bytes([0x05, 0x01, 0x00, 0x06, 0x02, 0x03, 0x03])
                else:
                    # Mock: PIN is default, 3 total retries, 3 remaining
                    # Tag 0x05: is_default = 0x01 (default)
                    # Tag 0x06: retries = 0x03 0x03 (total=3, remaining=3)
                    return bytes([0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03])

            elif p2 == 0x81:  # PUK metadata
                if device.pin_protected:
                    # PUK is NOT default (changed)
                    return bytes([0x05, 0x01, 0x00, 0x06, 0x02, 0x03, 0x03])
                else:
                    # Mock: PUK is default
                    return bytes([0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03])

            elif p2 == 0x9B:  # Management key metadata
                if device.pin_protected:
                    # Management key is NOT default (stored in PRINTED)
                    # Tag 0x01: algorithm = 0x03 (3DES)
                    # Tag 0x05: is_default = 0x00 (NOT default)
                    return bytes([0x01, 0x01, 0x03, 0x05, 0x01, 0x00])
                else:
                    # Mock: Management key is default
                    # Tag 0x01: algorithm = 0x03 (3DES)
                    # Tag 0x05: is_default = 0x01 (default)
                    return bytes([0x01, 0x01, 0x03, 0x05, 0x01, 0x01])

            else:
                raise RuntimeError(f"Unsupported metadata slot: {p2:#x}")

        # Other APDUs not implemented in emulation
        raise RuntimeError(f"Unsupported APDU in emulation: INS={ins:#x}")
