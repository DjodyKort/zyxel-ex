"""End-to-end handshake test against a fake in-memory Zyxel gateway.

The fake transport does exactly what a real gateway does: hands out an RSA
public key, RSA-decrypts the AES key the client wraps at login, and AES-encrypts
every response with that session key. So this exercises the complete
RSA+AES handshake and DAL read path with no hardware.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from zyxel_ex import ZyxelClient, ZyxelError, crypto


def _fake_gateway(*, expect_user: str = "admin", expect_pass: str = "s3cret") -> httpx.MockTransport:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    state: dict[str, bytes] = {}

    def enc(key: bytes, obj: dict[str, Any]) -> str:
        iv = crypto.gen_iv()
        return json.dumps(
            {"content": crypto.aes_encrypt(json.dumps(obj), key, iv), "iv": base64.b64encode(iv).decode()}
        )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/getRSAPublickKey":
            return httpx.Response(200, text=json.dumps({"RSAPublicKey": pub_pem, "result": "ZCFG_SUCCESS"}))
        if path == "/UserLogin":
            body = json.loads(request.content)
            aes_key_b64 = priv.decrypt(base64.b64decode(body["key"]), padding.PKCS1v15()).decode()
            key = base64.b64decode(aes_key_b64)
            state["key"] = key
            login = json.loads(crypto.aes_decrypt(body["content"], key, base64.b64decode(body["iv"])))
            ok = (
                login["Input_Account"] == expect_user
                and base64.b64decode(login["Input_Passwd"]).decode() == expect_pass
            )
            payload = {"sessionkey": "SK-123", "result": "ZCFG_SUCCESS"} if ok else {"result": "Invalid"}
            return httpx.Response(200, text=enc(key, payload))
        if path == "/cgi-bin/DAL":
            key = state["key"]
            oid = request.url.params.get("oid")
            data = {"result": "ZCFG_SUCCESS", "Object": [{"Index": 1, "Enable": True, "Description": oid}]}
            return httpx.Response(200, text=enc(key, data))
        return httpx.Response(200, text=json.dumps({"result": "ZCFG_SUCCESS"}))

    return httpx.MockTransport(handler)


def test_login_and_dal_read() -> None:
    z = ZyxelClient("gw", "admin", "s3cret", transport=_fake_gateway())
    z.login()
    assert z.session_key == "SK-123"
    rules = z.dal_list("nat")
    assert rules[0]["Description"] == "nat"


def test_context_manager() -> None:
    with ZyxelClient("gw", "admin", "s3cret", transport=_fake_gateway()) as z:
        assert z.dal_get("status")["result"] == "ZCFG_SUCCESS"


def test_bad_password_raises() -> None:
    z = ZyxelClient("gw", "admin", "wrong", transport=_fake_gateway())
    with pytest.raises(ZyxelError):
        z.login()
