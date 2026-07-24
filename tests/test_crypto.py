"""Crypto primitives: AES round-trip, the 16-byte-IV quirk, and RSA wrapping."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from zyxel_ex import crypto


def test_aes_roundtrip() -> None:
    key, iv = crypto.gen_key(), crypto.gen_iv()
    for msg in ("", "hi", '{"a": 1, "unicode": "€ ‑ ok"}' * 40):
        assert crypto.aes_decrypt(crypto.aes_encrypt(msg, key, iv), key, iv) == msg


def test_only_first_16_iv_bytes_matter() -> None:
    # The GUI ships a 32-byte IV but AES-CBC consumes only the first 16.
    key, iv = crypto.gen_key(), crypto.gen_iv()
    iv_tail_changed = iv[:16] + bytes(16)
    ct = crypto.aes_encrypt("payload", key, iv)
    assert crypto.aes_decrypt(ct, key, iv_tail_changed) == "payload"


def test_rsa_encrypt_is_pkcs1v15_of_the_text() -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    wrapped = base64.b64decode(crypto.rsa_encrypt("an-aes-key-in-base64==", pub_pem))
    assert priv.decrypt(wrapped, padding.PKCS1v15()).decode() == "an-aes-key-in-base64=="
