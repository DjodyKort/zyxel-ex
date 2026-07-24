"""Decode a Zyxel ``configuration-backupsettings.conf`` backup.

The backup is a short text header followed by a TIFF-style variable-width LZW
stream that decompresses to the device's config XML (passwords base64-encoded).
The LZW decompressor is a self-contained port of joeatwork/python-lzw (so there
is no fragile third-party dependency). Technique per iscilyas/zyxel-modem-backup-extract.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from typing import Any
from xml.etree import ElementTree as ET

CLEAR_CODE = 256
END_OF_INFO_CODE = 257
_INITIAL_CODE_SIZE = 258  # 0..255 + the two control codes
_MIN_WIDTH = 9


def _unpack(data: bytes) -> Iterator[int]:
    """Bit-unpack the variable-width LZW code stream (MSB-first) into codepoints."""
    codesize = _INITIAL_CODE_SIZE
    width = _MIN_WIDTH
    bits: list[int] = []
    offset = 0
    ignore = 0
    for byte in data:
        for shift in range(7, -1, -1):
            offset = (offset + 1) % 8
            if ignore > 0:
                ignore -= 1
                continue
            bits.append((byte >> shift) & 1)
            if len(bits) == width:
                cp = 0
                for b in bits:
                    cp = (cp << 1) | b
                bits = []
                yield cp
                codesize += 1
                if cp in (CLEAR_CODE, END_OF_INFO_CODE):
                    codesize = _INITIAL_CODE_SIZE
                    width = _MIN_WIDTH
                else:
                    while codesize >= (1 << width):
                        width += 1
                if cp == END_OF_INFO_CODE:
                    ignore = (8 - offset) % 8


def lzw_decompress(data: bytes) -> bytes:
    """Decompress a joeatwork/TIFF-style LZW byte stream."""
    out = bytearray()
    table: dict[int, bytes] = {}
    prefix: bytes | None = None

    def clear() -> None:
        nonlocal table, prefix
        table = {i: bytes([i]) for i in range(256)}
        table[CLEAR_CODE] = b""  # placeholders so new codes start at index 258
        table[END_OF_INFO_CODE] = b""
        prefix = None

    clear()
    for cp in _unpack(data):
        if cp == CLEAR_CODE:
            clear()
            continue
        if cp == END_OF_INFO_CODE:
            break
        if cp in table:
            entry = table[cp]
            if prefix is not None:
                table[len(table)] = prefix + entry[:1]
        else:  # KwKwK: code not yet in the table
            assert prefix is not None
            entry = prefix + prefix[:1]
            table[len(table)] = entry
        out += entry
        prefix = entry
    return bytes(out)


def decode_conf(data: bytes) -> bytes:
    """Strip the backup header and return the decompressed config XML bytes."""
    m = re.search(rb"<compressed\b[^>]*>", data)
    if m:
        # Data begins right after the header's closing '>' (optionally past a <crc=..> tag).
        start = m.end()
        crc = re.match(rb"\s*<crc=[^>]*>", data[start:])
        if crc:
            start += crc.end()
    else:
        start = 60  # firmware variant: a fixed 60-byte header
    return lzw_decompress(data[start:])


def extract_secrets(xml: bytes) -> dict[str, Any]:
    """Pull users, PPPoE, and Wi-Fi credentials out of the decoded config XML."""

    def b64(v: str | None) -> str:
        if not v:
            return ""
        try:
            return base64.b64decode(v).decode("utf-8", "replace").rstrip("\x00")
        except (ValueError, UnicodeDecodeError):
            return v

    root = ET.fromstring(xml)

    def text(node: ET.Element, tag: str) -> str | None:
        child = node.find(tag)
        return child.text if child is not None else None

    users = [
        {
            "username": text(n, "UserName"),
            "password": b64(text(n, "Password")),
            "enabled": (text(n, "Enable") or "").upper() != "FALSE",
        }
        for n in root.iter("Use_Login_Info")
        if text(n, "UserName")
    ]
    ppp = [
        {"username": text(n, "Username"), "password": b64(text(n, "Password"))}
        for n in root.iter("WANPPPConnection")
        if text(n, "Username")
    ]
    wifi = [
        {
            "ssid": text(n, "WlSsid"),
            "auth": text(n, "WlAuthMode"),
            "password": text(n, "WlWpaPsk"),
        }
        for n in root.iter("WlVirtIntfCfg")
        if text(n, "WlSsid")
    ]
    return {"users": users, "ppp": ppp, "wifi": wifi}
