"""End-to-end client tests against the in-memory fake gateway (see fake_gateway.py).

The fake does the real RSA+AES handshake, so these exercise the complete login,
encrypted DAL read/write and logout paths with no hardware.
"""

from __future__ import annotations

import pytest
from fake_gateway import FakeGateway

from zyxel_ex import ZyxelClient, ZyxelError


def test_login_and_dal_read() -> None:
    gw = FakeGateway(tables={"nat": [{"Index": 1, "Description": "ssh"}]})
    z = ZyxelClient("gw", "admin", "s3cret", transport=gw.transport)
    z.login()
    assert z.session_key == "SK-1"
    assert z.dal_list("nat")[0]["Description"] == "ssh"


def test_context_manager_logs_in_and_out() -> None:
    gw = FakeGateway()
    with ZyxelClient("gw", "admin", "s3cret", transport=gw.transport) as z:
        assert gw.logged_in
        assert z.dal_get("status")["result"] == "ZCFG_SUCCESS"
    assert not gw.logged_in


def test_bad_password_raises() -> None:
    gw = FakeGateway()
    with pytest.raises(ZyxelError):
        ZyxelClient("gw", "admin", "wrong", transport=gw.transport).login()


def test_update_item_echoes_the_device_record() -> None:
    # Firmware-specific fields the client knows nothing about must survive an edit.
    rule = {"Index": 1, "Enable": True, "Description": "ssh", "X_VENDOR_Field": 7}
    gw = FakeGateway(tables={"nat": [rule]})
    with ZyxelClient("gw", "admin", "s3cret", transport=gw.transport) as z:
        z.update_item("nat", 1, {"Enable": False})
    assert gw.writes == [("PUT", "nat", {**rule, "Enable": False})]


def test_update_item_unknown_index_raises() -> None:
    gw = FakeGateway(tables={"nat": []})
    with (
        ZyxelClient("gw", "admin", "s3cret", transport=gw.transport) as z,
        pytest.raises(ZyxelError, match="no record with Index 3"),
    ):
        z.update_item("nat", 3, {"Enable": False})


def test_delete_renumbers_like_the_gateway() -> None:
    gw = FakeGateway(tables={"nat": [{"Index": 1, "Description": "a"}, {"Index": 2, "Description": "b"}]})
    with ZyxelClient("gw", "admin", "s3cret", transport=gw.transport) as z:
        z.dal_delete("nat", 1)
        assert z.dal_list("nat") == [{"Index": 1, "Description": "b"}]
