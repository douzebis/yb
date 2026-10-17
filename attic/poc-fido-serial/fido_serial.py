#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Read YubiKey serial numbers over FIDO HID, as ykman does (spec 0028).

For each hidraw device with the FIDO usage page (0xF1D0), send CTAPHID
INIT, then Yubico's vendor command READ_CONFIG (0x42, page 0), and print
the serial (device info tag 0x02) and firmware version (tag 0x05).
Standard library only; needs read/write access to /dev/hidraw* (the udev
"uaccess" rules of libfido2 or systemd), not root.
"""

import glob
import os
import struct

FIDO_USAGE_PAGE = b"\x06\xd0\xf1"  # Usage Page (FIDO Alliance), 2-byte form
BROADCAST_CID = b"\xff\xff\xff\xff"
CTAPHID_INIT = 0x06
CTAPHID_ERROR = 0x3F
CTAPHID_KEEPALIVE = 0x3B
YK_READ_CONFIG = 0x42  # CTAP_VENDOR_FIRST + 2 (yubikit/management.py)
TYPE_INIT = 0x80
REPORT = 64


def fido_hidraw_devices():
    for sysdir in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            with open(os.path.join(sysdir, "device/report_descriptor"), "rb") as f:
                if FIDO_USAGE_PAGE in f.read():
                    yield "/dev/" + os.path.basename(sysdir), sysdir
        except OSError:
            pass


def send(fd, cid, cmd, data):
    """Send one CTAPHID message (INIT packet, then CONT packets)."""
    pkt = cid + bytes([TYPE_INIT | cmd]) + struct.pack(">H", len(data)) + data[:57]
    os.write(fd, b"\0" + pkt.ljust(REPORT, b"\0"))
    rest, seq = data[57:], 0
    while rest:
        pkt = cid + bytes([seq]) + rest[:59]
        os.write(fd, b"\0" + pkt.ljust(REPORT, b"\0"))
        rest, seq = rest[59:], seq + 1


def recv(fd, cid, cmd):
    """Receive one CTAPHID message for `cid`, skipping keepalives."""
    while True:
        pkt = os.read(fd, REPORT)
        if pkt[:4] != cid:
            continue
        if pkt[4] == TYPE_INIT | CTAPHID_KEEPALIVE:
            continue
        if pkt[4] == TYPE_INIT | CTAPHID_ERROR:
            raise RuntimeError(f"CTAPHID error 0x{pkt[7]:02x}")
        if pkt[4] != TYPE_INIT | cmd:
            raise RuntimeError(f"unexpected command 0x{pkt[4]:02x}")
        size = struct.unpack(">H", pkt[5:7])[0]
        data = pkt[7 : 7 + size]
        while len(data) < size:
            pkt = os.read(fd, REPORT)
            if pkt[:4] == cid:
                data += pkt[5 : 5 + size - len(data)]
        return data


def parse_tlvs(data):
    tlvs = {}
    while data:
        tag, length = data[0], data[1]
        off = 2
        if length == 0x81:
            length, off = data[2], 3
        elif length == 0x82:
            length, off = struct.unpack(">H", data[2:4])[0], 4
        tlvs[tag] = data[off : off + length]
        data = data[off + length :]
    return tlvs


def read_serial(path):
    fd = os.open(path, os.O_RDWR)
    try:
        nonce = os.urandom(8)
        send(fd, BROADCAST_CID, CTAPHID_INIT, nonce)
        resp = recv(fd, BROADCAST_CID, CTAPHID_INIT)
        while resp[:8] != nonce:  # another client's INIT reply
            resp = recv(fd, BROADCAST_CID, CTAPHID_INIT)
        cid = resp[8:12]
        major, minor, build = resp[13], resp[14], resp[15]
        info = recv_info(fd, cid)
    finally:
        os.close(fd)
    if len(info) - 1 != info[0]:
        raise RuntimeError("invalid device info length")
    tlvs = parse_tlvs(info[1:])
    serial = int.from_bytes(tlvs[0x02], "big") if 0x02 in tlvs else None
    version = ".".join(str(b) for b in tlvs.get(0x05, bytes([major, minor, build])))
    return serial, version


def recv_info(fd, cid):
    send(fd, cid, YK_READ_CONFIG, b"\x00")  # page 0
    return recv(fd, cid, YK_READ_CONFIG)


def main():
    found = False
    for path, sysdir in fido_hidraw_devices():
        found = True
        with open(os.path.join(sysdir, "device/uevent")) as f:
            uevent = f.read()
        name = next(
            (
                l.split("=", 1)[1]
                for l in uevent.splitlines()
                if l.startswith("HID_NAME=")
            ),
            "?",
        )
        try:
            serial, version = read_serial(path)
            print(f"{path}: {name}: serial {serial}, firmware {version}")
        except PermissionError:
            print(f"{path}: {name}: permission denied (no uaccess rule?)")
        except (OSError, RuntimeError) as e:
            print(f"{path}: {name}: {e}")
    if not found:
        print("no FIDO HID device found")


if __name__ == "__main__":
    main()
