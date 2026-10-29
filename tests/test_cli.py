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
            "cardpage_status": [{"IPAddress": "8.8.8.8"}],
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


def _rule(index: int, **fields: object) -> dict[str, object]:
    return {
        "Index": index, "Enable": True, "Description": f"rule {index}", "Protocol": "TCP", "Interface": "",
        "X_ZYXEL_AutoDetectWanStatus": True, "ExternalPortStart": 5648, "ExternalPortEnd": 5648,
        "InternalPortStart": 22, "InternalPortEnd": 22, "InternalClient": "192.168.1.21", **fields,
    }  # fmt: skip


def test_nat_list_flags_a_rule_bound_to_no_wan() -> None:
    gw = FakeGateway(tables={"nat": [_rule(1), _rule(2, X_ZYXEL_AutoDetectWanStatus=False)]})
    result = zyx(gw, "--password", "s3cret", "nat", "list")
    assert result.exit_code == 0, result.output
    rows = [line for line in result.output.splitlines() if "rule " in line]
    assert "any" in rows[0]
    assert "none" in rows[1]


def test_nat_edit_repairs_the_wan_binding_and_keeps_the_rest() -> None:
    broken = _rule(1, X_ZYXEL_AutoDetectWanStatus=False, X_VENDOR_Field=7)
    gw = FakeGateway(tables={"nat": [broken]})
    result = zyx(gw, "--password", "s3cret", "nat", "edit", "1", "--any-wan", "--int", "2222")
    assert result.exit_code == 0, result.output
    assert gw.tables["nat"][0] == {
        **broken, "X_ZYXEL_AutoDetectWanStatus": True, "InternalPortStart": 2222, "InternalPortEnd": 2222,
    }  # fmt: skip


def test_nat_edit_without_changes_is_a_usage_error() -> None:
    gw = FakeGateway(tables={"nat": [_rule(1)]})
    result = zyx(gw, "--password", "s3cret", "nat", "edit", "1")
    assert result.exit_code == 2
    assert gw.writes == []


def test_nat_rm_asks_first() -> None:
    gw = FakeGateway(tables={"nat": [_rule(1, Description="Home Server - SSH")]})
    declined = zyx(gw, "--password", "s3cret", "nat", "rm", "1", input="n\n")
    assert declined.exit_code == 1
    assert "'Home Server - SSH' (TCP 5648 → 192.168.1.21:22)" in declined.output
    assert len(gw.tables["nat"]) == 1
    assert zyx(gw, "--password", "s3cret", "nat", "rm", "1", "--yes").exit_code == 0
    assert gw.tables["nat"] == []


def test_nat_rm_unknown_index_is_an_error() -> None:
    gw = FakeGateway(tables={"nat": []})
    result = zyx(gw, "--password", "s3cret", "nat", "rm", "4", "--yes")
    assert result.exit_code == 1
    assert "no port-forward rule with index 4" in result.output


def test_nat_add_validates_port_and_address() -> None:
    gw = FakeGateway()
    base = ("--password", "s3cret", "nat", "add", "--name", "x")
    assert zyx(gw, *base, "--to", "192.168.1.21", "--ext", "70000").exit_code == 2
    assert zyx(gw, *base, "--to", "server.lan", "--ext", "22").exit_code == 2
    assert gw.writes == []
