"""`zyx` — command-line interface for Zyxel EX/AX/VMG (OPAL) gateways.

One small command per capability, each a thin wrapper over the DAL client's
``dal_get`` / ``dal_post`` / ``dal_put`` / ``dal_delete`` / ``update_item``.
Adding a capability = adding a command here.
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import json
import time
from collections.abc import Callable
from typing import Any

import click
import httpx
from rich.console import Console
from rich.table import Table

from . import backup as _backup
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
    # Lazy: don't connect (or prompt for a password) until a command needs the
    # gateway — so offline commands like `backup decode` work with no modem.
    client = ZyxelClient(host, user, password or "")
    client.login_sha512 = sha512
    ctx.obj = client
    ctx.call_on_close(client.close)


def needs_login(f: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a command so it logs into the gateway on first use (prompting for a
    password if none was supplied). Commands that don't touch the gateway skip it."""

    @functools.wraps(f)
    @click.pass_obj
    def wrapper(client: ZyxelClient, *args: Any, **kwargs: Any) -> Any:
        if not client.session_key:
            if not client.password:
                client.password = click.prompt("Password", hide_input=True)
            try:
                client.login(sha512=client.login_sha512)
            except ZyxelError as e:
                raise click.ClickException(str(e)) from e
        return f(client, *args, **kwargs)

    return wrapper


def _objects(client: ZyxelClient, oid: str) -> list[dict[str, Any]]:
    return client.dal_list(oid)


def _port_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _yn(value: Any) -> str:
    return "[green]✓" if value else "[dim]—"


# ── system ────────────────────────────────────────────────────────────────


@cli.command()
@needs_login
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
@needs_login
def info(client: ZyxelClient) -> None:
    """Full device info as JSON."""
    console.print_json(json.dumps(client.device_info()))


@cli.command()
@click.confirmation_option(prompt="Reboot the gateway now?")
@needs_login
def reboot(client: ZyxelClient) -> None:
    """Reboot the gateway."""
    client.dal_post("reboot", {})
    console.print("[yellow]reboot requested — the gateway will drop offline shortly.")


@cli.command()
@needs_login
def wan(client: ZyxelClient) -> None:
    """WAN connection: public IP, gateway, DNS, uptime."""
    w = _wan_iface(client)
    if not w:
        console.print("[yellow]no active WAN interface with a public IP found")
        return
    t = Table(show_header=False, box=None)
    rows = [
        ("Public IP", w.get("IPAddress", "")),
        ("Gateway", w.get("v4Gateway", "")),
        ("DNS", w.get("DNSServer", "")),
        ("Type", w.get("AddressingType", "")),
        ("Status", w.get("Status", "")),
    ]
    for label, val in rows:
        if val:
            t.add_row(f"[bold]{label}", str(val))
    up = w.get("ipoeConnectionUpTime") or w.get("UpTime")
    if up:
        t.add_row("[bold]Uptime", _fmt_uptime(up))
    console.print(t)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global


def _wan_iface(client: ZyxelClient) -> dict[str, Any]:
    """The interface record carrying a public IPv4 (WAN), found recursively so it
    works regardless of where a given firmware nests it in `cardpage_status`."""

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            if _is_public_ip(o.get("IPAddress", "")):
                yield o
            for v in o.values():
                yield from walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from walk(v)

    candidates: list[dict[str, Any]] = list(walk(client.dal_get("cardpage_status")))
    # Prefer the fuller interface record (the one that also carries gateway/DNS).
    for c in candidates:
        if c.get("v4Gateway") or c.get("DNSServer"):
            return c
    return candidates[0] if candidates else {}


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
@needs_login
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
@needs_login
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
@needs_login
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
@needs_login
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
            # An empty Interface only means "any WAN" with auto-detect on; without it the
            # gateway accepts the rule but binds it to no WAN, so nothing is forwarded.
            "Interface": "",
            "X_ZYXEL_AutoDetectWanStatus": True,
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
@needs_login
def nat_enable(client: ZyxelClient, index: int) -> None:
    """Enable rule INDEX."""
    client.update_item("nat", index, {"Enable": True})
    console.print(f"[green]enabled[/] rule {index}")


@nat.command("disable")
@click.argument("index", type=int)
@needs_login
def nat_disable(client: ZyxelClient, index: int) -> None:
    """Disable rule INDEX."""
    client.update_item("nat", index, {"Enable": False})
    console.print(f"[yellow]disabled[/] rule {index}")


@nat.command("rm")
@click.argument("index", type=int)
@needs_login
def nat_rm(client: ZyxelClient, index: int) -> None:
    """Delete rule INDEX."""
    client.dal_delete("nat", index)
    console.print(f"[green]deleted[/] rule {index}")


# ── wifi ────────────────────────────────────────────────────────────────────


@cli.group()
def wifi() -> None:
    """Wi-Fi radios / SSIDs."""


@wifi.command("list")
@needs_login
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
@needs_login
def wifi_enable(client: ZyxelClient, index: int) -> None:
    """Enable SSID INDEX."""
    client.update_item("wlan", index, {"wlEnable": True})
    console.print(f"[green]enabled[/] SSID {index}")


@wifi.command("disable")
@click.argument("index", type=int)
@needs_login
def wifi_disable(client: ZyxelClient, index: int) -> None:
    """Disable SSID INDEX (this will disconnect its clients)."""
    client.update_item("wlan", index, {"wlEnable": False})
    console.print(f"[yellow]disabled[/] SSID {index}")


# ── dns / dhcp / firewall (read for now; writes land in v0.2.x) ─────────────


@cli.command()
@needs_login
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
@needs_login
def firewall(client: ZyxelClient) -> None:
    """Firewall ACL rules."""
    console.print_json(json.dumps(_objects(client, "firewall_acl")))


# ── prometheus exporter ─────────────────────────────────────────────────────


@cli.command()
@click.option("--serve", is_flag=True, help="Run an HTTP /metrics server instead of printing once")
@click.option("--port", default=9100, show_default=True, type=int)
@needs_login
def metrics(client: ZyxelClient, serve: bool, port: int) -> None:
    """Prometheus metrics — print once, or `--serve` an HTTP exporter."""
    if not serve:
        click.echo(_metrics_text(client), nl=False)
        return

    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib API)
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            try:
                body = _metrics_text(client)
            except ZyxelError:
                client.login()
                body = _metrics_text(client)
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # quiet

    console.print(f"[dim]serving metrics on http://0.0.0.0:{port}/metrics — Ctrl+C to stop[/]")
    with contextlib.suppress(KeyboardInterrupt):
        HTTPServer(("0.0.0.0", port), Handler).serve_forever()


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _metrics_text(client: ZyxelClient) -> str:
    dev = client.device_info()
    active = [d for d in _lan_devices(client) if d.get("Active")]
    wifi = [d for d in active if d.get("InterfaceType") == "Wi-Fi"]
    lines = [
        "# HELP zyxel_up 1 if the gateway responded",
        "# TYPE zyxel_up gauge",
        "zyxel_up 1",
        "# TYPE zyxel_connected_devices gauge",
        f'zyxel_connected_devices{{type="all"}} {len(active)}',
        f'zyxel_connected_devices{{type="wifi"}} {len(wifi)}',
        "# TYPE zyxel_nat_rules gauge",
        f"zyxel_nat_rules {len(client.dal_list('nat'))}",
        "# TYPE zyxel_wan_up gauge",
        f"zyxel_wan_up {1 if _wan_iface(client) else 0}",
        "# TYPE zyxel_info gauge",
        f'zyxel_info{{model="{_esc(dev.get("ModelName", ""))}",'
        f'firmware="{_esc(dev.get("SoftwareVersion", ""))}"}} 1',
    ]
    up = dev.get("UpTime")
    if up:
        lines += ["# TYPE zyxel_uptime_seconds gauge", f"zyxel_uptime_seconds {int(up)}"]
    lines.append("# TYPE zyxel_device_online gauge")
    for d in active:
        labels = (
            f'mac="{_esc(d.get("PhysAddress", ""))}",'
            f'name="{_esc(d.get("HostName", "") or "?")}",'
            f'ip="{_esc(d.get("IPAddress", ""))}"'
        )
        lines.append(f"zyxel_device_online{{{labels}}} 1")
    return "\n".join(lines) + "\n"


# ── raw power tools ─────────────────────────────────────────────────────────


@cli.command()
@click.argument("oid")
@needs_login
def get(client: ZyxelClient, oid: str) -> None:
    """Dump the decrypted JSON for any OID (e.g. `zyx get wlan`)."""
    console.print_json(json.dumps(client.dal_get(oid)))


@cli.command("set")
@click.argument("oid")
@click.argument("json_body")
@needs_login
def set_(client: ZyxelClient, oid: str, json_body: str) -> None:
    """POST a raw JSON record to an OID (advanced): `zyx set nat '{"Enable":true,...}'`."""
    console.print_json(json.dumps(client.dal_post(oid, json.loads(json_body))))


@cli.command()
def oids() -> None:
    """List commonly-used OIDs."""
    console.print("\n".join(KNOWN_OIDS))


# ── config backup (offline — no gateway needed) ─────────────────────────────


@cli.group()
def backup() -> None:
    """Decode a Zyxel `.conf` configuration backup."""


@backup.command("decode")
@click.argument("conf_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--secrets", is_flag=True, help="Extract users / PPPoE / Wi-Fi credentials")
@click.option("--out", type=click.Path(dir_okay=False), help="Write to a file instead of stdout")
def backup_decode(conf_file: str, secrets: bool, out: str | None) -> None:
    """Decode a router backup (download it via Maintenance → Backup first).

    Strips the header, LZW-decompresses the config XML, then prints the XML — or,
    with --secrets, the users / PPPoE / Wi-Fi credentials as JSON.
    """
    with open(conf_file, "rb") as fh:
        xml = _backup.decode_conf(fh.read())
    if secrets:
        payload = json.dumps(_backup.extract_secrets(xml), indent=2)
        if out:
            with open(out, "w", encoding="utf-8") as fh2:
                fh2.write(payload)
            console.print(f"[green]wrote[/] {out}")
        else:
            console.print_json(payload)
    elif out:
        with open(out, "wb") as fh3:
            fh3.write(xml)
        console.print(f"[green]wrote[/] {out} ({len(xml)} bytes)")
    else:
        click.echo(xml.decode("utf-8", "replace"))


if __name__ == "__main__":
    cli()
