"""TLS pinning, sha512 re-login and keyring-backed credentials."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import httpx
import keyring
import pytest
from click.testing import CliRunner
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from zyxel_ex import PinMismatchError, ZyxelClient, credentials, crypto
from zyxel_ex.cli import cli

CERT = b"fake DER certificate"
CERT_SHA = hashlib.sha256(CERT).hexdigest()


class _SSLObject:
    def __init__(self, der: bytes | None) -> None:
        self.der = der

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        return self.der


class _Stream:
    def __init__(self, der: bytes | None) -> None:
        self.ssl = _SSLObject(der)

    def get_extra_info(self, name: str) -> Any:
        return self.ssl if name == "ssl_object" else None


def _response(der: bytes | None) -> httpx.Response:
    return httpx.Response(200, text="{}", extensions={"network_stream": _Stream(der)})


class MemoryKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if self.store.pop((service, username), None) is None:
            raise PasswordDeleteError(username)


@pytest.fixture
def memory_keyring() -> MemoryKeyring:
    backend = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    yield backend  # type: ignore[misc]
    keyring.set_keyring(previous)


def test01_pin_accepts_matching_cert_in_any_notation() -> None:
    colons = ":".join(CERT_SHA[i : i + 2] for i in range(0, len(CERT_SHA), 2)).upper()
    ZyxelClient("gw", pin=colons)._check_pin(_response(CERT))


def test02_pin_rejects_other_cert() -> None:
    with pytest.raises(PinMismatchError, match="does not match"):
        ZyxelClient("gw", pin="00" * 32)._check_pin(_response(CERT))


def test03_pin_fails_closed_without_a_readable_cert() -> None:
    with pytest.raises(PinMismatchError, match="could not be read"):
        ZyxelClient("gw", pin=CERT_SHA)._check_pin(httpx.Response(200, text="{}"))


def test04_relogin_reuses_the_sha512_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    z = ZyxelClient("gw", "admin", "pw")
    z.login_sha512 = True
    monkeypatch.setattr(z, "_get_json", lambda path: {"RSAPublicKey": "unused"})
    monkeypatch.setattr("zyxel_ex.crypto.rsa_encrypt", lambda text, key: "wrapped")

    def fake_post(path: str, body: str, headers: dict[str, str]) -> str:
        outer = json.loads(body)
        plain = crypto.aes_decrypt(outer["content"], z.aes_key, base64.b64decode(outer["iv"]))
        sent.append(json.loads(plain))
        return json.dumps({"sessionkey": "SK", "result": "ZCFG_SUCCESS"})

    monkeypatch.setattr(z, "_post_raw", fake_post)
    z.login()
    assert sent[0]["SHA512_password"] is True
    assert sent[0]["Input_Passwd"] == hashlib.sha512(b"pw").hexdigest()


def test05_credentials_roundtrip(memory_keyring: MemoryKeyring) -> None:
    assert credentials.password("gw", "admin") is None
    credentials.save("gw", "admin", "pw", CERT_SHA)
    assert credentials.password("gw", "admin") == "pw"
    assert credentials.pin("gw") == CERT_SHA
    assert credentials.forget("gw", "admin") is True
    assert credentials.forget("gw", "admin") is False
    assert credentials.pin("gw") is None


def test06_cli_uses_keyring_password_and_pin(
    memory_keyring: MemoryKeyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials.save("gw", "admin", "from-keyring", CERT_SHA)
    seen: dict[str, Any] = {}

    def fake_login(self: ZyxelClient, *, sha512: bool | None = None) -> dict[str, Any]:
        seen.update(password=self.password, pin=self.pin)
        self.session_key = "SK"
        return {}

    monkeypatch.delenv("ZY_PASS", raising=False)
    monkeypatch.delenv("ZY_PIN", raising=False)
    monkeypatch.setattr(ZyxelClient, "login", fake_login)
    monkeypatch.setattr(ZyxelClient, "dal_list", lambda self, oid: [])
    result = CliRunner().invoke(cli, ["--host", "gw", "nat", "list"])
    assert result.exit_code == 0, result.output
    assert seen == {"password": "from-keyring", "pin": CERT_SHA}


def test07_auth_save_pins_and_stores(memory_keyring: MemoryKeyring, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZY_PIN", raising=False)
    monkeypatch.setattr("zyxel_ex.cli.cert_fingerprint", lambda host: CERT_SHA)
    monkeypatch.setattr(ZyxelClient, "login", lambda self, **kw: {})
    result = CliRunner().invoke(cli, ["--host", "gw", "--password", "pw", "auth", "save", "--yes"])
    assert result.exit_code == 0, result.output
    assert credentials.password("gw", "admin") == "pw"
    assert credentials.pin("gw") == CERT_SHA
