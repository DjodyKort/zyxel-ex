"""`zyx` — command-line interface for Zyxel EX/AX/VMG (OPAL) gateways.

One small command per capability, each a thin wrapper over the DAL client's
``dal_get`` / ``dal_post`` / ``dal_put`` / ``dal_delete`` / ``update_item``.
Adding a capability = adding a command here.
"""

from __future__ import annotations

import contextlib
import functools
import io
import ipaddress
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import httpx
from dotenv import dotenv_values
from keyring.errors import KeyringError
from rich.console import Console
from rich.table import Table

from . import __version__, credentials
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

# The .env keys `zyx` reads, and the option each one fills in.
ENV_FILE_KEYS = {
    "ZY_HOST": "host",
    "ZY_USER": "user",
    "ZY_PASS": "password",
    "ZY_PIN": "pin",
    "ZY_SHA512": "sha512",
}


def find_env_file(cwd: Path, home: Path) -> Path | None:
    """The ``.env`` to use when none is named: the working directory's, else the user's."""
    for candidate in (cwd / ".env", home / ".config" / "zyxel-ex" / ".env"):
        if candidate.is_file():
            return candidate
    return None


def _load_env_file(ctx: click.Context, param: click.Parameter, path: str | None) -> None:
    # Eager, so it runs before the other options read their defaults. The values become
    # defaults, not environment: a flag or a real ZY_* variable still overrides the file.
    if not path:
        return
    values = dotenv_values(path)
    defaults = {option: values[key] for key, option in ENV_FILE_KEYS.items() if values.get(key)}
    ctx.default_map = {**(ctx.default_map or {}), **defaults}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="zyx")
@click.option(
    "--env-file",
    envvar="ZY_ENV_FILE",
    type=click.Path(exists=True, dir_okay=False),
    is_eager=True,
    expose_value=False,
    callback=_load_env_file,
    help="Read ZY_* settings from this file [default: ./.env, else ~/.config/zyxel-ex/.env]",
)
@click.option("--host", envvar="ZY_HOST", default="192.168.1.1", show_default=True, help="Gateway IP")
@click.option("--user", envvar="ZY_USER", default="admin", show_default=True, help="Admin username")
@click.option(
    "--password",
    envvar="ZY_PASS",
    help="Admin password. Prefer `zyx auth save` (OS keyring) or ZY_PASS: flags end up in shell history",
)
@click.option("--pin", envvar="ZY_PIN", help="Expected SHA-256 of the gateway's TLS cert (see `zyx cert`)")
@click.option(
    "--sha512", envvar="ZY_SHA512", is_flag=True, help="Hash the password (some firmware variants require it)"
)
@click.pass_context
def cli(
    ctx: click.Context, host: str, user: str, password: str | None, pin: str | None, sha512: bool
) -> None:
    """Scriptable control for Zyxel EX/AX/VMG (OPAL) home gateways.

    The password comes from --password / ZY_PASS, else the OS keyring (`zyx auth save`),
    else a prompt. The TLS pin comes from --pin / ZY_PIN, else the keyring.
    """
    # Lazy: don't connect (or prompt for a password) until a command needs the
    # gateway — so offline commands like `backup decode` work with no modem.
    # Callers may hand in an httpx transport as `obj` (the tests use a fake gateway).
    transport = ctx.obj if isinstance(ctx.obj, httpx.BaseTransport) else None
    client = ZyxelClient(host, user, password or "", pin=pin, transport=transport)
    client.login_sha512 = sha512
    ctx.obj = client
    ctx.call_on_close(client.close)


def needs_login(f: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a command so it logs into the gateway on first use (prompting for a
    password if none was supplied). Commands that don't touch the gateway skip it."""

    @functools.wraps(f)
    @click.pass_obj
    def wrapper(client: ZyxelClient, *args: Any, **kwargs: Any) -> Any:
        # A gateway refusal (duplicate rule, bad value, expired session) is an answer for the
        # user, not a crash: print it as one line instead of a traceback.
        try:
            if not client.session_key:
                if client.pin is None:
                    client.pin = credentials.pin(client.host)
                if not client.password:
                    client.password = credentials.password(client.host, client.username) or click.prompt(
                        "Password", hide_input=True
                    )
                client.login()
            return f(client, *args, **kwargs)
        except ZyxelError as e:
            raise click.ClickException(str(e)) from e

    return wrapper


def _objects(client: ZyxelClient, oid: str) -> list[dict[str, Any]]:
    return client.dal_list(oid)


def _port_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _yn(value: Any) -> str:
    return "[green]✓" if value else "[dim]—"


# ── auth ──────────────────────────────────────────────────────────────────


@cli.command()
@click.pass_obj
def cert(client: ZyxelClient) -> None:
    """Print the SHA-256 fingerprint of the gateway's TLS certificate (for --pin / ZY_PIN)."""
    try:
        click.echo(client.fetch_fingerprint())
    except ZyxelError as e:
        raise click.ClickException(str(e)) from e


@cli.group()
def auth() -> None:
    """Credentials in the OS keyring."""


@auth.command("save")
@click.option("-y", "--yes", is_flag=True, help="Trust the gateway's current certificate without asking")
@click.pass_obj
def auth_save(client: ZyxelClient, yes: bool) -> None:
    """Check the password against the gateway, then store it plus the gateway's TLS pin."""
    if not client.pin:
        # Trust on first use, like SSH: show the fingerprint once, pin it from then on.
        try:
            fingerprint = client.fetch_fingerprint()
        except ZyxelError as e:
            raise click.ClickException(str(e)) from e
        console.print(f"certificate SHA-256 of {client.host}: [bold]{fingerprint}")
        if not yes:
            click.confirm("Trust this certificate?", default=True, abort=True)
        client.pin = fingerprint
    if not client.password:
        client.password = click.prompt("Password", hide_input=True)
    try:
        client.login()
        credentials.save(client.host, client.username, client.password, client.pin)
    except ZyxelError as e:
        raise click.ClickException(str(e)) from e
    except KeyringError as e:
        raise click.ClickException(f"no usable OS keyring here ({e}); use ZY_PASS / ZY_PIN instead") from e
    console.print(f"[green]saved[/] {client.username}@{client.host} and its certificate pin")


@auth.command("forget")
@click.pass_obj
def auth_forget(client: ZyxelClient) -> None:
    """Remove the stored password and pin for this host/user."""
    if credentials.forget(client.host, client.username):
        console.print(f"[yellow]forgot[/] {client.username}@{client.host}")
    else:
        console.print(f"[dim]nothing stored for {client.username}@{client.host}")


@auth.command("status")
@click.pass_obj
def auth_status(client: ZyxelClient) -> None:
    """Show where the password and TLS pin for this host/user come from."""
    stored_pin = credentials.pin(client.host)
    if client.password:
        pw_source = "--password / ZY_PASS"
    elif credentials.password(client.host, client.username):
        pw_source = "keyring"
    else:
        pw_source = "[yellow]none (will prompt)"
    if client.pin:
        pin_source = f"--pin / ZY_PIN ({client.pin})"
    elif stored_pin:
        pin_source = f"keyring ({stored_pin})"
    else:
        pin_source = "[red]none: the gateway's identity is not checked"
    t = Table(show_header=False, box=None)
    t.add_row("[bold]Gateway", f"{client.username}@{client.host}")
    t.add_row("[bold]Password", pw_source)
    t.add_row("[bold]TLS pin", pin_source)
    console.print(t)


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
                devices = _refreshing(client, _lan_devices)
            except ZyxelError as e:
                # The gateway rebooting or a Wi-Fi blip must not end a long-running watch.
                console.print(f"[dim]poll failed ({e}); retrying in {interval}s[/]")
                time.sleep(interval)
                continue
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


def _refreshing(client: ZyxelClient, read: Callable[[ZyxelClient], Any]) -> Any:
    """Run a read; if it fails, log in again once (sessions expire) and retry."""
    try:
        return read(client)
    except ZyxelError:
        client.login()
        return read(client)


def _track_event(ntfy: str | None, kind: str, name: str, mac: str) -> None:
    color = "green" if kind == "joined" else "yellow"
    console.print(f"[{color}]●[/] [bold]{name}[/] ({mac}) {kind}")
    if ntfy:
        with contextlib.suppress(httpx.HTTPError):
            httpx.post(ntfy, content=f"{name} ({mac}) {kind}".encode(), timeout=5)


# ── nat / port forwarding ───────────────────────────────────────────────────


PORT = click.IntRange(1, 65535)
PROTOCOLS = click.Choice(["TCP", "UDP", "ALL"])


def _ipv4(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    if value is not None:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise click.BadParameter(f"{value!r} is not an IPv4 address") from None
    return value


def _nat_wan(rule: dict[str, Any]) -> str:
    """The WAN a rule listens on. An empty Interface means "any" only with auto-detect on;
    a rule bound to none is accepted and listed by the gateway, but forwards nothing."""
    if rule.get("Interface"):
        return str(rule["Interface"])
    # Firmware without the field has no such state, so treat it as "any".
    return "any" if rule.get("X_ZYXEL_AutoDetectWanStatus", True) else "[red]none"


def _describe_rule(rule: dict[str, Any]) -> str:
    ext = _port_range(rule["ExternalPortStart"], rule["ExternalPortEnd"])
    internal = _port_range(rule["InternalPortStart"], rule["InternalPortEnd"])
    return (
        f"'{rule.get('Description', '')}' "
        f"({rule.get('Protocol', '')} {ext} → {rule.get('InternalClient', '')}:{internal})"
    )


@cli.group()
def nat() -> None:
    """Port-forwarding rules."""


@nat.command("list")
@needs_login
def nat_list(client: ZyxelClient) -> None:
    """List port-forward rules."""
    t = Table(title="Port forwarding")
    for col in ("Idx", "On", "Name", "Proto", "WAN", "WAN port", "→ Host", "Host port"):
        t.add_column(col)
    for r in _objects(client, "nat"):
        t.add_row(
            str(r["Index"]),
            _yn(r["Enable"]),
            r["Description"],
            r["Protocol"],
            _nat_wan(r),
            _port_range(r["ExternalPortStart"], r["ExternalPortEnd"]),
            r["InternalClient"],
            _port_range(r["InternalPortStart"], r["InternalPortEnd"]),
        )
    console.print(t)


@nat.command("add")
@click.option("--name", required=True, help="Rule description")
@click.option("--to", "internal_client", required=True, callback=_ipv4, help="Internal host IP")
@click.option("--ext", "ext_port", required=True, type=PORT, help="External (WAN) port")
@click.option("--int", "int_port", type=PORT, help="Internal port (default: same as --ext)")
@click.option("--proto", type=PROTOCOLS, default="TCP", show_default=True)
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


@nat.command("edit")
@click.argument("index", type=int)
@click.option("--name", help="New description")
@click.option("--to", "internal_client", callback=_ipv4, help="New internal host IP")
@click.option("--ext", "ext_port", type=PORT, help="New external (WAN) port")
@click.option("--int", "int_port", type=PORT, help="New internal port")
@click.option("--proto", type=PROTOCOLS, help="New protocol")
@click.option("--any-wan", is_flag=True, help="Listen on any WAN (repairs a rule whose WAN shows 'none')")
@needs_login
def nat_edit(
    client: ZyxelClient,
    index: int,
    name: str | None,
    internal_client: str | None,
    ext_port: int | None,
    int_port: int | None,
    proto: str | None,
    any_wan: bool,
) -> None:
    """Change rule INDEX in place; every field not given stays as it is."""
    changes: dict[str, Any] = {}
    if name is not None:
        changes["Description"] = name
    if internal_client is not None:
        changes["InternalClient"] = internal_client
    if ext_port is not None:
        changes.update(ExternalPortStart=ext_port, ExternalPortEnd=ext_port)
    if int_port is not None:
        changes.update(InternalPortStart=int_port, InternalPortEnd=int_port)
    if proto is not None:
        changes["Protocol"] = proto
    if any_wan:
        changes.update(Interface="", X_ZYXEL_AutoDetectWanStatus=True)
    if not changes:
        raise click.UsageError("nothing to change: give at least one option")
    client.update_item("nat", index, changes)
    console.print(f"[green]updated[/] rule {index}")


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
@click.option("-y", "--yes", is_flag=True, help="Delete without asking")
@needs_login
def nat_rm(client: ZyxelClient, index: int, yes: bool) -> None:
    """Delete rule INDEX.

    The gateway renumbers the rules after it, so list again before the next delete.
    """
    rule = next((r for r in _objects(client, "nat") if r.get("Index") == index), None)
    if rule is None:
        raise click.ClickException(f"no port-forward rule with index {index}")
    if not yes:
        click.confirm(f"Delete rule {index} {_describe_rule(rule)}?", abort=True)
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
    """Static DHCP reservations (IP <-> MAC bindings)."""
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
@click.option(
    "--bind",
    default="127.0.0.1",
    show_default=True,
    help="Listen address; 0.0.0.0 exposes device names/MACs/IPs to the whole network, unauthenticated",
)
@needs_login
def metrics(client: ZyxelClient, serve: bool, port: int, bind: str) -> None:
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
                body = _refreshing(client, _metrics_text)
            except ZyxelError:
                # Prometheus convention: a scrape still answers, and zyxel_up says why it is empty.
                body = "# TYPE zyxel_up gauge\nzyxel_up 0\n"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # quiet

    console.print(f"[dim]serving metrics on http://{bind}:{port}/metrics — Ctrl+C to stop[/]")
    with contextlib.suppress(KeyboardInterrupt):
        HTTPServer((bind, port), Handler).serve_forever()


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


def main() -> None:
    """Console entry point."""
    # A non-UTF-8 console (Windows cp1252, or output piped on Windows) cannot encode every
    # character rich and the help texts use; degrade those to '?' instead of crashing.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper) and (stream.encoding or "").lower() not in ("utf-8", "utf8"):
            stream.reconfigure(errors="replace")
    env_file = find_env_file(Path.cwd(), Path.home())
    cli.main(default_map={"env_file": str(env_file)} if env_file else None)


if __name__ == "__main__":
    main()
