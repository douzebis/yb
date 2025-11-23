#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
YubiKey Selection with Interactive Menu and LED Feedback.

Uses prompt_toolkit for arrow-key navigation and flashes the selected YubiKey.
"""

from __future__ import annotations

import threading
import time
from typing import Hashable, Protocol, cast

from prompt_toolkit import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl


class PcscConnection(Protocol):
    """Protocol for pyscard connection object (accessed via conn.connection)."""

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """Send APDU and receive response."""
        ...


class ScardSmartCardConnection(Protocol):
    """Protocol for ykman.pcsc.ScardSmartCardConnection."""

    connection: PcscConnection

    def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
        """Send APDU and receive response (yubikit API)."""
        ...


def flash_yubikey_continuously(device_obj, stop_event: threading.Event) -> None:
    """
    Flash the LED of the YubiKey continuously.

    Args:
        device_obj: The ykman device object to flash
        stop_event: Event to signal when to stop flashing

    Continues flashing until stop_event is set.
    """
    try:
        from yubikit.core.smartcard import SmartCardConnection

        # Keep connection open for the entire flashing period
        # This avoids the overhead of reopening the connection each time
        with device_obj.open_connection(SmartCardConnection) as _conn:
            conn = cast(ScardSmartCardConnection, _conn)

            # PIV AID: A0 00 00 03 08
            piv_aid = [0xA0, 0x00, 0x00, 0x03, 0x08]
            select_apdu = [0x00, 0xA4, 0x04, 0x00, len(piv_aid)] + piv_aid

            # Flash continuously until stopped
            while not stop_event.is_set():
                try:
                    # SELECT PIV application - causes LED flash
                    conn.connection.transmit(select_apdu)

                    # Wait a bit before next flash
                    # Check stop_event more frequently for responsiveness
                    for _ in range(2):  # 2 x 100ms = 200ms between flashes
                        if stop_event.is_set():
                            break
                        time.sleep(0.1)

                except Exception:
                    # If transmission fails, break out and close connection
                    # (device might have been removed)
                    break

    except Exception:
        # Silently ignore errors during flashing setup
        pass


class YubiKeySelector:
    """Interactive YubiKey selector with arrow-key navigation and LED feedback."""

    def __init__(
        self,
        devices: list[tuple[int | None, str]],
        device_objects: list
    ) -> None:
        """
        Initialize the selector with device information.

        Args:
            devices: List of (serial, version) tuples for display
            device_objects: List of ykman device objects for flashing
        """
        self.devices = devices
        self.device_objects = device_objects
        self.selected_index = 0
        self.selected_serial: int | None = None
        self.flash_thread: threading.Thread | None = None
        self.stop_flash_event: threading.Event | None = None

    def get_formatted_text(self) -> FormattedText:
        """Generate the formatted text for the menu display."""
        lines: list[tuple[str, str]] = []

        lines.append(("", "\n"))
        lines.append(("bold", "Select a YubiKey:\n"))
        lines.append(("", "\n"))

        for i, (serial, version) in enumerate(self.devices):
            if i == self.selected_index:
                # Highlighted selection
                lines.append(("bg:#00aa00 fg:#ffffff", f"  → YubiKey {serial}"))
                lines.append(("bg:#00aa00 fg:#ffffff", f" (v{version})  \n"))
            else:
                # Normal display
                lines.append(("", f"    YubiKey {serial}"))
                lines.append(("", f" (v{version})\n"))

        lines.append(("", "\n"))
        lines.append(("", "Use ↑/↓ arrows to navigate, ENTER to select, Ctrl-C to cancel\n"))

        return FormattedText(lines)

    def flash_selected(self) -> None:
        """Flash the currently selected YubiKey continuously in a background thread."""
        # Stop any existing flashing thread
        if self.stop_flash_event is not None:
            self.stop_flash_event.set()
        if self.flash_thread is not None and self.flash_thread.is_alive():
            self.flash_thread.join(timeout=0.5)

        # Start new flashing thread for currently selected device
        if 0 <= self.selected_index < len(self.device_objects):
            device_obj = self.device_objects[self.selected_index]
            # Only flash if we have a valid device object
            if device_obj is not None:
                self.stop_flash_event = threading.Event()
                self.flash_thread = threading.Thread(
                    target=flash_yubikey_continuously,
                    args=(device_obj, self.stop_flash_event),
                    daemon=True
                )
                self.flash_thread.start()

    def move_up(self) -> None:
        """Move selection up."""
        if self.selected_index > 0:
            self.selected_index -= 1
            self.flash_selected()

    def move_down(self) -> None:
        """Move selection down."""
        if self.selected_index < len(self.devices) - 1:
            self.selected_index += 1
            self.flash_selected()

    def confirm_selection(self, app: Application) -> None:
        """Confirm the current selection and exit."""
        self.selected_serial = int(str(self.devices[self.selected_index][0]))
        # Stop flashing
        if self.stop_flash_event is not None:
            self.stop_flash_event.set()
        app.exit()

    def run(self) -> int | None:
        """Run the interactive selector and return the selected serial."""
        # Flash the initially selected YubiKey
        self.flash_selected()

        # Create key bindings
        kb = KeyBindings()

        @kb.add("up")
        def move_up_handler(event) -> None:
            self.move_up()
            event.app.invalidate()

        @kb.add("down")
        def move_down_handler(event) -> None:
            self.move_down()
            event.app.invalidate()

        @kb.add("enter")
        def confirm_handler(event) -> None:
            self.confirm_selection(event.app)

        @kb.add("c-c")
        def cancel_handler(event) -> None:
            # Stop flashing before exit
            if self.stop_flash_event is not None:
                self.stop_flash_event.set()
            event.app.exit()

        # Create the layout
        control = FormattedTextControl(text=self.get_formatted_text)
        window = Window(content=control, always_hide_cursor=True)
        layout = Layout(window)

        # Create and run the application
        app: Application = Application(
            layout=layout, key_bindings=kb, full_screen=False, mouse_support=False
        )

        app.run()

        return self.selected_serial


def select_yubikey_interactively(devices: list[tuple[int | None, str, Hashable]]) -> int | None:
    """
    Interactively select a YubiKey from multiple devices.

    Args:
        devices: List of (serial, version, reader) tuples

    Returns:
        Selected serial number, or None if cancelled or failed

    Raises:
        ImportError: If prompt_toolkit is not available
    """
    try:
        from ykman.device import list_all_devices

        # Get device objects from ykman (needed for flashing)
        # Only enumerate once, not repeatedly!
        all_devices = list_all_devices()

        # Match devices to the ones we were given (by serial number)
        device_objects = []
        device_list = []
        for serial, version, _ in devices:
            for dev_obj, dev_info in all_devices:
                if dev_info.serial == serial:
                    device_objects.append(dev_obj)
                    device_list.append((serial, version))
                    break

        if not device_objects:
            # Fallback: if we can't match devices, just show the list without flashing
            device_list = [(serial, version) for serial, version, _ in devices]
            # Create dummy objects
            device_objects = [None] * len(device_list)

        selector = YubiKeySelector(device_list, device_objects)
        return selector.run()

    except ImportError:
        # If ykman not available, fall back to simple selector without flashing
        device_list = [(serial, version) for serial, version, _ in devices]
        device_objects = [None] * len(device_list)
        selector = YubiKeySelector(device_list, device_objects)
        return selector.run()
