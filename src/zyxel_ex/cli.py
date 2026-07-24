"""`zyx` — command-line interface for Zyxel EX/AX gateways."""

from __future__ import annotations

import json
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from .client import ZyxelClient, ZyxelError

console = Console()

# OIDs the OPAL firmware exposes (from the GUI's app.js). Grows over time.
KNOWN_OIDS = [
    "status",
    "wan",
    "lan",
    "lanhosts",
    "nat",
    "nat_trigger",
    "nat_addr_map",
    "static_dhcp",
    "static_route",
    "dns",
    "firewall_acl",
    "firewall_proto",
    "wlan",
    "user_account",
    "scheduler",
    "qos",
    "cellwan_status",
    "usb_info",
]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", envvar="ZY_HOST", default="192.168.1.1", show_default=True, help="Gateway IP")
@click.option("--user", envvar="ZY_USER", default="admin", show_default=True, help="Admin username")
@click.option("--password", envvar="ZY_PASS", help="Admin password (or set ZY_PASS)")
@click.pass_context
def cli(ctx: click.Context, host: str, user: str, password: str | None) -> None:
    """Scriptable control for Zyxel EX/AX (OPAL) home gateways."""
    if not password:
        password = click.prompt("Password", hide_input=True)
    client = ZyxelClient(host, user, password)
    try:
        client.login()
    except ZyxelError as e:
        raise click.ClickException(str(e)) from e
    ctx.obj = client
    ctx.call_on_close(client.close)


def _objects(client: ZyxelClient, oid: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = client.dal_get(oid).get("Object", [])
    return objects


# -- status ----------------------------------------------------------------


@cli.command()
@click.pass_obj
def status(client: ZyxelClient) -> None:
    """Show device + WAN summary."""
    info = _objects(client, "status")
    dev: dict[str, Any] = next((o["DeviceInfo"] for o in info if o.get("DeviceInfo")), {})
    t = Table(title="Device", show_header=False)
    for k in ("ModelName", "SerialNumber", "SoftwareVersion", "UpTime"):
        if k in dev:
            t.add_row(k, str(dev[k]))
    console.print(t)


# -- nat / port forwarding -------------------------------------------------


@cli.group()
def nat() -> None:
    """Port-forwarding rules."""


@nat.command("list")
@click.pass_obj
def nat_list(client: ZyxelClient) -> None:
    """List port-forward rules."""
    rules = _objects(client, "nat")
    t = Table(title="Port forwarding")
    for col in ("Idx", "On", "Name", "Proto", "WAN port", "→ Host", "Host port"):
        t.add_column(col)
    for r in rules:
        ext = _port_range(r["ExternalPortStart"], r["ExternalPortEnd"])
        internal = _port_range(r["InternalPortStart"], r["InternalPortEnd"])
        t.add_row(
            str(r["Index"]),
            "[green]✓" if r["Enable"] else "[red]✗",
            r["Description"],
            r["Protocol"],
            ext,
            r["InternalClient"],
            internal,
        )
    console.print(t)


@nat.command("add")
@click.option("--name", required=True, help="Rule description")
@click.option("--to", "internal_client", required=True, help="Internal host IP (e.g. 192.168.1.21)")
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
    rule = {
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
    }
    client.dal_post("nat", rule)
    console.print(f"[green]added[/] {name}: WAN {ext_port} → {internal_client}:{ip} ({proto})")


@nat.command("rm")
@click.argument("index", type=int)
@click.pass_obj
def nat_rm(client: ZyxelClient, index: int) -> None:
    """Delete the port-forward rule at INDEX (see `nat list`)."""
    client.dal_delete("nat", index)
    console.print(f"[green]deleted[/] rule {index}")


def _port_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


# -- hosts -----------------------------------------------------------------


@cli.command()
@click.option("--wifi", "wifi_only", is_flag=True, help="Only Wi-Fi clients")
@click.option("--active/--all", default=True, help="Only active hosts (default) or every known lease")
@click.pass_obj
def hosts(client: ZyxelClient, wifi_only: bool, active: bool) -> None:
    """List connected LAN / Wi-Fi devices."""
    obj = _objects(client, "lanhosts")
    devices: list[dict[str, Any]] = obj[0].get("lanhosts", []) if obj else []
    t = Table(title="Connected devices")
    for col in ("Host", "IP", "MAC", "Connection", "Signal", "OS", "On"):
        t.add_column(col)
    for h in devices:
        if wifi_only and h.get("InterfaceType") != "Wi-Fi":
            continue
        if active and not h.get("Active"):
            continue
        sig = h.get("X_ZYXEL_SignalStrength")
        bars = "".join("▁▂▄▆█"[min(sig, 4)]) if isinstance(sig, int) and sig > 0 else ""
        t.add_row(
            h.get("HostName", "") or "?",
            h.get("IPAddress", ""),
            h.get("PhysAddress", ""),
            h.get("X_ZYXEL_ConnectionType") or h.get("InterfaceType", ""),
            bars if h.get("InterfaceType") == "Wi-Fi" else "",
            (h.get("X_ZYXEL_OperatingSystem") or "").strip(),
            "[green]✓" if h.get("Active") else "[dim]—",
        )
    console.print(t)


# -- raw / power tools -----------------------------------------------------


@cli.command()
@click.argument("oid")
@click.pass_obj
def get(client: ZyxelClient, oid: str) -> None:
    """Dump the raw decrypted JSON for any OID (e.g. `zyx get wlan`)."""
    console.print_json(json.dumps(client.dal_get(oid)))


@cli.command()
def oids() -> None:
    """List commonly-used OIDs."""
    console.print("\n".join(KNOWN_OIDS))


if __name__ == "__main__":
    cli()
