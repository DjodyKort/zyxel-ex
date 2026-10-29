"""CLI payload tests: what each write command actually sends to the gateway."""

from __future__ import annotations

from typing import Any

import pytest
from click.testing import CliRunner

from zyxel_ex import ZyxelClient
from zyxel_ex.cli import cli


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_login(self: ZyxelClient, *, sha512: bool = False) -> dict[str, Any]:
        self.session_key = "SK-test"
        return {"result": "ZCFG_SUCCESS"}

    def fake_post(self: ZyxelClient, oid: str, data: dict[str, Any]) -> dict[str, Any]:
        calls.append((oid, data))
        return {"result": "ZCFG_SUCCESS"}

    monkeypatch.setattr(ZyxelClient, "login", fake_login)
    monkeypatch.setattr(ZyxelClient, "dal_post", fake_post)
    return calls


def test_nat_add_binds_rule_to_any_wan(posted: list[tuple[str, dict[str, Any]]]) -> None:
    args = ["--password", "x", "nat", "add", "--name", "SSH", "--to", "192.168.1.21", "--ext", "5648"]
    result = CliRunner().invoke(cli, [*args, "--int", "22"])
    assert result.exit_code == 0, result.output
    oid, rule = posted[0]
    assert oid == "nat"
    assert rule["Interface"] == ""
    assert rule["X_ZYXEL_AutoDetectWanStatus"] is True
    assert (rule["Protocol"], rule["ExternalPortStart"], rule["InternalPortStart"]) == ("TCP", 5648, 22)
