"""CLI behaviour against the fake gateway: what each command sends, and what it prints."""

from __future__ import annotations

from fake_gateway import FakeGateway, zyx

from zyxel_ex import ZyxelClient
from zyxel_ex.cli import _refreshing


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


def test_gateway_refusal_is_a_clean_error() -> None:
    gw = FakeGateway()
    gw.rejections["nat"] = "InternalClientPort is duplicate."
    result = zyx(
        gw, "--password", "s3cret", "nat", "add", "--name", "a", "--to", "192.168.1.2", "--ext", "80"
    )
    assert result.exit_code == 1
    assert "Error: nat: ZCFG_INVALID_PARAM_VALUE (InternalClientPort is duplicate.)" in result.output
    assert "Traceback" not in result.output


def test_refreshing_logs_in_again_after_session_expiry() -> None:
    gw = FakeGateway(tables={"nat": [{"Index": 1}]})
    with ZyxelClient("gw", "admin", "s3cret", transport=gw.transport) as z:
        gw.expire_session()
        assert _refreshing(z, lambda c: c.dal_list("nat")) == [{"Index": 1}]
    assert gw.logins == 2


def test_watch_survives_a_rebooting_gateway() -> None:
    gw = FakeGateway(tables={"lanhosts": [{"lanhosts": [{"PhysAddress": "AA", "Active": True}]}]})
    gw.fail_reads = 3  # first poll fails even after a re-login; the second succeeds
    result = zyx(gw, "--password", "s3cret", "watch", "--interval", "0", "--count", "1")
    assert result.exit_code == 0, result.output
    assert "poll failed" in result.output
    assert "1 devices online" in result.output


def test_metrics_prints_prometheus_text() -> None:
    gw = FakeGateway(
        tables={
            "status": [{"DeviceInfo": {"ModelName": "EX5601-T1", "SoftwareVersion": "V5", "UpTime": 60}}],
            "lanhosts": [{"lanhosts": [{"PhysAddress": "AA", "HostName": "pc", "Active": True}]}],
            "nat": [{"Index": 1}],
            "cardpage_status": [{"IPAddress": "188.90.155.181"}],
        }
    )
    result = zyx(gw, "--password", "s3cret", "metrics")
    assert result.exit_code == 0, result.output
    for line in (
        "zyxel_up 1",
        "zyxel_nat_rules 1",
        "zyxel_wan_up 1",
        'zyxel_device_online{mac="AA",name="pc"',
    ):
        assert line in result.output
