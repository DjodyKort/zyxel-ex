"""CLI behaviour against the fake gateway: what each command sends, and what it prints."""

from __future__ import annotations

from fake_gateway import FakeGateway, zyx


def test_nat_add_binds_rule_to_any_wan() -> None:
    gw = FakeGateway()
    result = zyx(
        gw, "--password", "s3cret", "nat", "add", "--name", "SSH", "--to", "192.168.1.21", "--ext", "5648",
        "--int", "22",
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    method, oid, rule = gw.writes[0]
    assert (method, oid) == ("POST", "nat")
    assert rule["Interface"] == ""
    assert rule["X_ZYXEL_AutoDetectWanStatus"] is True
    assert (rule["Protocol"], rule["ExternalPortStart"], rule["InternalPortStart"]) == ("TCP", 5648, 22)
