"""`zyx` — command-line interface for Zyxel EX/AX/VMG (OPAL) gateways.

One small command per capability, each a thin wrapper over the DAL client's
``dal_get`` / ``dal_post`` / ``dal_put`` / ``dal_delete`` / ``update_item``.
Adding a capability = adding a command here.
"""

from __future__ import annotations

import contextlib
import json
import time
from typing import Any

import click
import httpx
from rich.console import Console
from rich.table import Table

from .client import ZyxelClient, ZyxelError

console = Console()

# OIDs the OPAL firmware exposes (from the GUI's app.js). Not exhaustive.
KNOWN_OIDS = [
    "status", "wan", "lan", "lanhosts", "nat", "nat_trigger", "nat_addr_map",
    "static_dhcp", "static_route", "dns", "dns_route", "firewall_acl", "firewall_proto",
    "wlan", "wifi_easy_mesh", "user_account", "scheduler", "qos", "cellwan_status",
    "usb_info", "MultiWan", "ethwanlan", "port_mirror", "ipalias", "policy_route",
]  # fmt: skip


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", envvar="ZY_HOST", default="192.168.1.1", show_default=True, help="Gateway IP")
@click.option("--user", envvar="ZY_USER", default="admin", show_default=True, help="Admin username")
@click.option("--password", envvar="ZY_PASS", help="Admin password (or set ZY_PASS)")
@click.option("--sha512", is_flag=True, help="Hash the password (some firmware variants require it)")
@click.pass_context
def cli(ctx: click.Context, host: str, user: str, password: str | None, sha512: bool) -> None:
    """Scriptable control for Zyxel EX/AX/VMG (OPAL) home gateways."""
    if not password:
        password = click.prompt("Password", hide_input=True)
    client = ZyxelClient(host, user, password)
    try:
        client.login(sha512=sha512)
    except ZyxelError as e:
        raise click.ClickException(str(e)) from e
    ctx.obj = client
    ctx.call_on_close(client.close)


def _objects(client: ZyxelClient, oid: str) -> list[dict[str, Any]]:
    return client.dal_list(oid)


def _port_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _yn(value: Any) -> str:
    return "[green]✓" if value else "[dim]—"


# ── system ────────────────────────────────────────────────────────────────


@cli.command()
@click.pass_obj
def status(client: ZyxelClient) -> None:
    """Device + firmware summary."""
    dev = client.device_info()
    t = Table(show_header=False, box=None)
    for label, key in [
        ("Model", "ModelName"),
        ("Firmware", "SoftwareVersion"),
        ("Serial", "SerialNumber"),
        ("Uptime", "UpTime"),
    ]:
        if key in dev:
            val = _fmt_uptime(dev[key]) if key == "UpTime" else str(dev[key])
            t.add_row(f"[bold]{label}", val)
    console.print(t)


@cli.command()
@click.pass_obj
def info(client: ZyxelClient) -> None:
    """Full device info as JSON."""
    console.print_json(json.dumps(client.device_info()))


@cli.command()
@click.confirmation_option(prompt="Reboot the gateway now?")
@click.pass_obj
def reboot(client: ZyxelClient) -> None:
    """Reboot the gateway."""
    client.dal_post("reboot", {})
    console.print("[yellow]reboot requested — the gateway will drop offline shortly.")


def _fmt_uptime(seconds: Any) -> str:
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return f"{d}d {h}h {m}m"


# ── hosts (device tracking) ─────────────────────────────────────────────────


@cli.command()
@click.option("--wifi", "wifi_only", is_flag=True, help="Only Wi-Fi clients")
@click.option("--active/--all", default=True, help="Only active hosts (default) or every known lease")
@click.pass_obj
def hosts(client: ZyxelClient, wifi_only: bool, active: bool) -> None:
    """Connected LAN / Wi-Fi devices."""
    devices = _lan_devices(client)
    t = Table(title="Connected devices")
    for col in ("Host", "IP", "MAC", "Connection", "Signal", "OS", "On"):
        t.add_column(col)
    for h in devices:
        if wifi_only and h.get("InterfaceType") != "Wi-Fi":
            continue
        if active and not h.get("Active"):
            continue
        sig = h.get("X_ZYXEL_SignalStrength")
        bars = "▁▂▄▆█"[min(sig, 4)] if isinstance(sig, int) and sig > 0 else ""
        t.add_row(
            h.get("HostName", "") or "?",
            h.get("IPAddress", ""),
            h.get("PhysAddress", ""),
            h.get("X_ZYXEL_ConnectionType") or h.get("InterfaceType", ""),
            bars if h.get("InterfaceType") == "Wi-Fi" else "",
            (h.get("X_ZYXEL_OperatingSystem") or "").strip(),
            _yn(h.get("Active")),
        )
    console.print(t)


def _lan_devices(client: ZyxelClient) -> list[dict[str, Any]]:
    obj = client.dal_list("lanhosts")
    devices: list[dict[str, Any]] = obj[0].get("lanhosts", []) if obj else []
    return devices


@cli.command()
@click.option("--interval", default=15, show_default=True, type=int, help="Poll interval (seconds)")
@click.option("--ntfy", metavar="URL", help="ntfy topic URL to push join/leave events to")
@click.option("--count", default=0, type=int, help="Stop after N polls (0 = until Ctrl+C)")
@click.pass_obj
def watch(client: ZyxelClient, interval: int, ntfy: str | None, count: int) -> None:
    """Watch devices joining/leaving the network (Ctrl+C to stop)."""
    seen: dict[str, str] = {}
    polls = 0
    console.print(f"[dim]watching {client.host} every {interval}s — Ctrl+C to stop[/]")
    try:
        while True:
            try:
                devices = _lan_devices(client)
            except ZyxelError:
                client.login()  # refresh an expired session
                devices = _lan_devices(client)
            current = {
                d["PhysAddress"].lower(): (d.get("HostName") or "?")
                for d in devices
                if d.get("Active") and d.get("PhysAddress")
            }
            if seen:
                for mac in current.keys() - seen.keys():
                    _track_event(ntfy, "joined", current[mac], mac)
                for mac in seen.keys() - current.keys():
                    _track_event(ntfy, "left", seen[mac], mac)
            elif not polls:
                console.print(f"[dim]{len(current)} devices online[/]")
            seen = current
            polls += 1
            if count and polls >= count:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped[/]")


def _track_event(ntfy: str | None, kind: str, name: str, mac: str) -> None:
    color = "green" if kind == "joined" else "yellow"
    console.print(f"[{color}]●[/] [bold]{name}[/] ({mac}) {kind}")
    if ntfy:
        with contextlib.suppress(httpx.HTTPError):
            httpx.post(ntfy, content=f"{name} ({mac}) {kind}".encode(), timeout=5)


# ── nat / port forwarding ───────────────────────────────────────────────────


@cli.group()
def nat() -> None:
    """Port-forwarding rules."""


@nat.command("list")
@click.pass_obj
def nat_list(client: ZyxelClient) -> None:
    """List port-forward rules."""
    t = Table(title="Port forwarding")
    for col in ("Idx", "On", "Name", "Proto", "WAN port", "→ Host", "Host port"):
        t.add_column(col)
    for r in _objects(client, "nat"):
        t.add_row(
            str(r["Index"]),
            _yn(r["Enable"]),
            r["Description"],
            r["Protocol"],
            _port_range(r["ExternalPortStart"], r["ExternalPortEnd"]),
            r["InternalClient"],
            _port_range(r["InternalPortStart"], r["InternalPortEnd"]),
        )
    console.print(t)


@nat.command("add")
@click.option("--name", required=True, help="Rule description")
@click.option("--to", "internal_client", required=True, help="Internal host IP")
@click.option("--ext", "ext_port", required=True, type=int, help="External (WAN) port")
@click.option("--int", "int_port", type=int, help="Internal port (default: same as --ext)")
@click.option("--proto", type=click.Choice(["TCP", "UDP", "ALL"]), default="TCP", show_default=True)
@click.option("--disabled", is_flag=True, help="Create the rule disabled")
@click.pass_obj
def nat_add(
    client: ZyxelClient,
    name: str,
    internal_client: str,
    ext_port: int,
    int_port: int | None,
    proto: str,
    disabled: bool,
) -> None:
    """Add a port-forward rule."""
    ip = int_port if int_port is not None else ext_port
    client.dal_post(
        "nat",
        {
            "Enable": not disabled,
            "Protocol": proto,
            "Description": name,
            "Interface": "",
            "ExternalPortStart": ext_port,
            "ExternalPortEnd": ext_port,
            "InternalPortStart": ip,
            "InternalPortEnd": ip,
            "InternalClient": internal_client,
            "SetRemoteIP": False,
            "RemoteHost": "",
        },
    )
    console.print(f"[green]added[/] {name}: WAN {ext_port} → {internal_client}:{ip} ({proto})")


@nat.command("enable")
@click.argument("index", type=int)
@click.pass_obj
def nat_enable(client: ZyxelClient, index: int) -> None:
    """Enable rule INDEX."""
    client.update_item("nat", index, {"Enable": True})
    console.print(f"[green]enabled[/] rule {index}")


@nat.command("disable")
@click.argument("index", type=int)
@click.pass_obj
def nat_disable(client: ZyxelClient, index: int) -> None:
    """Disable rule INDEX."""
    client.update_item("nat", index, {"Enable": False})
    console.print(f"[yellow]disabled[/] rule {index}")


@nat.command("rm")
@click.argument("index", type=int)
@click.pass_obj
def nat_rm(client: ZyxelClient, index: int) -> None:
    """Delete rule INDEX."""
    client.dal_delete("nat", index)
    console.print(f"[green]deleted[/] rule {index}")


# ── wifi ────────────────────────────────────────────────────────────────────


@cli.group()
def wifi() -> None:
    """Wi-Fi radios / SSIDs."""


@wifi.command("list")
@click.pass_obj
def wifi_list(client: ZyxelClient) -> None:
    """List Wi-Fi SSIDs."""
    t = Table(title="Wi-Fi")
    for col in ("Idx", "On", "SSID", "Band", "Security", "Hidden"):
        t.add_column(col)
    for w in _objects(client, "wlan"):
        t.add_row(
            str(w.get("Index", "")),
            _yn(w.get("wlEnable", w.get("Enable"))),
            w.get("SSID", ""),
            str(w.get("band", "") or w.get("Band", "")),
            w.get("Security", "") or w.get("SecurityMode", ""),
            _yn(w.get("HideSSID") or w.get("SSIDHide")),
        )
    console.print(t)


@wifi.command("enable")
@click.argument("index", type=int)
@click.pass_obj
def wifi_enable(client: ZyxelClient, index: int) -> None:
    """Enable SSID INDEX."""
    client.update_item("wlan", index, {"wlEnable": True})
    console.print(f"[green]enabled[/] SSID {index}")


@wifi.command("disable")
@click.argument("index", type=int)
@click.pass_obj
def wifi_disable(client: ZyxelClient, index: int) -> None:
    """Disable SSID INDEX (this will disconnect its clients)."""
    client.update_item("wlan", index, {"wlEnable": False})
    console.print(f"[yellow]disabled[/] SSID {index}")


# ── dns / dhcp / firewall (read for now; writes land in v0.2.x) ─────────────


@cli.command()
@click.pass_obj
def dhcp(client: ZyxelClient) -> None:
    """Static DHCP reservations (IP ⇔ MAC bindings)."""
    names = {d.get("PhysAddress", "").lower(): d.get("HostName", "") for d in _lan_devices(client)}
    t = Table(title="DHCP reservations")
    for col in ("Idx", "On", "Host", "MAC", "IP"):
        t.add_column(col)
    for r in _objects(client, "static_dhcp"):
        mac = r.get("MACAddr", "") or r.get("MACAddress", "")
        t.add_row(
            str(r.get("Index", "")),
            _yn(r.get("Enable")),
            names.get(mac.lower(), ""),
            mac,
            r.get("IPAddr", "") or r.get("IPAddress", ""),
        )
    console.print(t)


@cli.command()
@click.pass_obj
def firewall(client: ZyxelClient) -> None:
    """Firewall ACL rules."""
    console.print_json(json.dumps(_objects(client, "firewall_acl")))


# ── raw power tools ─────────────────────────────────────────────────────────


@cli.command()
@click.argument("oid")
@click.pass_obj
def get(client: ZyxelClient, oid: str) -> None:
    """Dump the decrypted JSON for any OID (e.g. `zyx get wlan`)."""
    console.print_json(json.dumps(client.dal_get(oid)))


@cli.command("set")
@click.argument("oid")
@click.argument("json_body")
@click.pass_obj
def set_(client: ZyxelClient, oid: str, json_body: str) -> None:
    """POST a raw JSON record to an OID (advanced): `zyx set nat '{"Enable":true,...}'`."""
    console.print_json(json.dumps(client.dal_post(oid, json.loads(json_body))))


@cli.command()
def oids() -> None:
    """List commonly-used OIDs."""
    console.print("\n".join(KNOWN_OIDS))


if __name__ == "__main__":
    cli()
