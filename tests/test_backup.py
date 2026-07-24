"""Backup decoder: LZW port verified against joeatwork/python-lzw's own vector."""

from __future__ import annotations

import base64

from zyxel_ex.backup import extract_secrets, lzw_decompress

# The exact encode/decode pair from joeatwork/python-lzw's ByteEncoder doctest.
_ENCODED = b'3\x98LF#\x08\x82\x05\x04\x83\x1eM\xf0x\x1c\x16\x1b\t\x88C\xe1q(4"\x1f\x17\x85C#1X\xec.\x00'
_DECODED = b"gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo"


def test_lzw_decompress_matches_reference_vector() -> None:
    assert lzw_decompress(_ENCODED) == _DECODED


def test_extract_secrets() -> None:
    pw = base64.b64encode(b"hunter2").decode()
    xml = (
        "<Root>"
        f"<Use_Login_Info><UserName>admin</UserName><Password>{pw}</Password>"
        "<Enable>TRUE</Enable></Use_Login_Info>"
        "<WlVirtIntfCfg><WlSsid>MyWifi</WlSsid><WlAuthMode>psk2</WlAuthMode>"
        "<WlWpaPsk>secret123</WlWpaPsk></WlVirtIntfCfg>"
        "</Root>"
    ).encode()
    secrets = extract_secrets(xml)
    assert secrets["users"][0] == {"username": "admin", "password": "hunter2", "enabled": True}
    assert secrets["wifi"][0]["ssid"] == "MyWifi"
    assert secrets["wifi"][0]["password"] == "secret123"
