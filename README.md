# zyxel-ex

Scriptable Python client + `zyx` CLI for **Zyxel EX/AX** home gateways running the
**OPAL** firmware (e.g. the **EX5601-T1** shipped by Odido NL), via the router's
encrypted **DAL** web API — no browser, no cloud.

## Why

The GUI is a Vue app that talks to `/cgi-bin/DAL?oid=…` over an RSA-wraps-AES
handshake (RSA public key → random AES-256 key → AES-CBC/PKCS7 JSON, session
`sessionkey` sent as the `CSRFToken` header on writes). This package replicates
that handshake so you can read and change gateway config from scripts.

Reverse-engineered from the router's own `app.js`; the write path cross-checks
against [`millaguie/zyxel-cli`](https://github.com/millaguie/zyxel-cli).

## Install

```bash
uv pip install -e ".[dev]"     # or: pip install -e .
```

## Use

```bash
export ZY_HOST=192.168.1.1 ZY_USER=admin ZY_PASS='…'

zyx status                 # model / firmware / uptime
zyx hosts [--wifi]         # connected devices (signal, OS) — device tracking
zyx dhcp                   # static DHCP reservations (with device names)
zyx wifi list              # SSIDs / bands / security
zyx wifi disable 2         # toggle an SSID (2.4G/5G/guest)
zyx nat list               # port-forward rules
zyx nat add --name "My app" --to 192.168.1.21 --ext 8443 --proto TCP
zyx nat disable 5          # enable / disable / rm a rule
zyx firewall               # firewall ACLs
zyx reboot                 # reboot the gateway
zyx get <oid>              # raw decrypted JSON for any OID
zyx set <oid> '{…}'        # POST a raw record (advanced)
zyx oids                   # commonly-used OIDs
```

Writes are **model-agnostic**: toggles/edits read the device's own record and
write it back with only your change applied, so they work across firmware
variants (which use different field names) without special-casing.

As a library:

```python
from zyxel_ex import ZyxelClient

with ZyxelClient("192.168.1.1", "admin", "…") as z:
    for rule in z.dal_get("nat")["Object"]:
        print(rule["Description"], rule["ExternalPortStart"])
```

## Security

- Talks to the gateway over its self-signed HTTPS (cert verification off for the LAN).
- Credentials come from env/flags — nothing is stored. Treat `ZY_PASS` like any secret.

## Compatibility

Built and live-tested against the **EX5601-T1** (Odido NL, OPAL_2.0 firmware).
The DAL handshake is shared across the OPAL EX/AX/VMG/DX families, so other
models should work — reports welcome. If your firmware wants a hashed password,
add `--sha512`.

| Model | Status |
|---|---|
| EX5601-T1 | ✅ verified (status, hosts, nat CRUD, wifi, dhcp) |
| other EX/AX/VMG/DX (OPAL) | 🧪 should work — please report |

## Status

v0.2 — model-agnostic client, robust login, and commands for
status/info/reboot/hosts/nat (full CRUD)/wifi/dhcp/firewall + raw get/set. Built
to grow: each capability is a small CLI command over a `dal_*` call.

Roadmap: `.conf` backup decoder · Prometheus exporter · device-tracking watch
mode (+ntfy) · pytest + CI + PyPI · async client.

## License

MIT
