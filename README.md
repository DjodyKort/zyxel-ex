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

zyx status                 # device + WAN summary
zyx hosts                  # connected LAN devices
zyx nat list               # port-forward rules
zyx nat add --name "My app" --to 192.168.1.21 --ext 8443 --proto TCP
zyx nat rm 5               # delete rule 5
zyx get wlan               # raw decrypted JSON for any OID
zyx oids                   # commonly-used OIDs
```

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

## Status

v0.1 — login, DAL read/write/delete, and commands for status/hosts/nat. Built to
grow: each new capability is a small CLI command over a `dal_get`/`dal_post` call.

## License

MIT
