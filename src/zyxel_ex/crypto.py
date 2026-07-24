"""The Zyxel OPAL web-API crypto primitives.

Reverse-engineered from the router's own ``/static/js/app.js`` (functions
``AesRsaEncrypt`` / ``AesDecrypt``) and cross-checked against community work
(millaguie/zyxel-cli). The GUI generates a random AES-256 key + IV per session,
AES-CBC/PKCS7 encrypts each JSON payload, and RSA(PKCS1v1.5)-encrypts the base64
AES key once at login. The router replies with ``{content, iv}`` ciphertext.

Note: the GUI uses a 32-byte "IV" but AES-CBC only consumes the first 16 bytes;
we replicate that (encrypt with ``iv[:16]``, transmit the full value).
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import padding as _sympad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as _asympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_BLOCK_BITS = 128


def gen_key() -> bytes:
    """A fresh 32-byte AES-256 session key."""
    return os.urandom(32)


def gen_iv() -> bytes:
    """A fresh 32-byte IV (only the first 16 bytes are used by AES-CBC)."""
    return os.urandom(32)


def aes_encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    padder = _sympad.PKCS7(_BLOCK_BITS).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv[:16])).encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def aes_decrypt(content_b64: str, key: bytes, iv: bytes) -> str:
    ct = base64.b64decode(content_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv[:16])).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = _sympad.PKCS7(_BLOCK_BITS).unpadder()
    return (unpad.update(padded) + unpad.finalize()).decode()


def rsa_encrypt(text: str, public_key_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    return base64.b64encode(pub.encrypt(text.encode(), _asympad.PKCS1v15())).decode()  # type: ignore[union-attr]
