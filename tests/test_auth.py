"""TLS pinning, hashed-password login and keyring-backed credentials."""

from __future__ import annotations

import pytest
from fake_gateway import FakeGateway, zyx

from zyxel_ex import PinMismatchError, ZyxelClient, ZyxelError, credentials


def _colon_notation(fingerprint: str) -> str:
    return ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)).upper()


def test_pin_accepts_matching_cert_in_any_notation() -> None:
    gw = FakeGateway()
    z = ZyxelClient("gw", "admin", "s3cret", pin=_colon_notation(gw.fingerprint), transport=gw.transport)
    z.login()
    assert gw.logins == 1


def test_pin_mismatch_stops_before_the_password_is_sent() -> None:
    gw = FakeGateway()
    z = ZyxelClient("gw", "admin", "s3cret", pin="00" * 32, transport=gw.transport)
    with pytest.raises(PinMismatchError, match="does not match"):
        z.login()
    assert gw.login_attempts == 0


def test_pin_fails_closed_without_a_certificate() -> None:
    gw = FakeGateway(cert=b"")
    z = ZyxelClient("gw", "admin", "s3cret", pin="00" * 32, transport=gw.transport)
    with pytest.raises(PinMismatchError, match="could not be read"):
        z.login()


def test_fetch_fingerprint_ignores_the_pin() -> None:
    gw = FakeGateway()
    z = ZyxelClient("gw", pin="00" * 32, transport=gw.transport)
    assert z.fetch_fingerprint() == gw.fingerprint


def test_login_follows_login_sha512() -> None:
    gw = FakeGateway(sha512=True)
    plain = ZyxelClient("gw", "admin", "s3cret", transport=gw.transport)
    with pytest.raises(ZyxelError):
        plain.login()
    hashed = ZyxelClient("gw", "admin", "s3cret", transport=gw.transport)
    hashed.login_sha512 = True
    hashed.login()
    hashed.login()  # a session refresh must hash too
    assert gw.logins == 2


def test_credentials_roundtrip() -> None:
    assert credentials.password("gw", "admin") is None
    credentials.save("gw", "admin", "pw", "ab" * 32)
    assert credentials.password("gw", "admin") == "pw"
    assert credentials.pin("gw") == "ab" * 32
    assert credentials.forget("gw", "admin") is True
    assert credentials.forget("gw", "admin") is False
    assert credentials.pin("gw") is None


def test_cli_logs_in_from_the_keyring() -> None:
    gw = FakeGateway(tables={"nat": []})
    credentials.save("gw", "admin", "s3cret", gw.fingerprint)
    result = zyx(gw, "--host", "gw", "nat", "list")
    assert result.exit_code == 0, result.output
    assert gw.logins == 1


def test_cli_enforces_the_stored_pin() -> None:
    gw = FakeGateway()
    credentials.save("gw", "admin", "s3cret", "00" * 32)
    result = zyx(gw, "--host", "gw", "nat", "list")
    assert result.exit_code == 1
    assert "does not match the pin" in result.output
    assert gw.login_attempts == 0


def test_cert_prints_the_fingerprint() -> None:
    gw = FakeGateway()
    result = zyx(gw, "--host", "gw", "cert")
    assert result.output.strip() == gw.fingerprint


def test_auth_save_pins_and_stores() -> None:
    gw = FakeGateway()
    result = zyx(gw, "--host", "gw", "--password", "s3cret", "auth", "save", "--yes")
    assert result.exit_code == 0, result.output
    assert credentials.password("gw", "admin") == "s3cret"
    assert credentials.pin("gw") == gw.fingerprint


def test_auth_save_stores_nothing_on_a_wrong_password() -> None:
    gw = FakeGateway()
    result = zyx(gw, "--host", "gw", "--password", "wrong", "auth", "save", "--yes")
    assert result.exit_code == 1
    assert credentials.password("gw", "admin") is None
    assert credentials.pin("gw") is None


def test_auth_save_stops_when_the_certificate_is_not_trusted() -> None:
    gw = FakeGateway()
    result = zyx(gw, "--host", "gw", "--password", "s3cret", "auth", "save", input="n\n")
    assert result.exit_code == 1
    assert gw.login_attempts == 0
    assert credentials.password("gw", "admin") is None
