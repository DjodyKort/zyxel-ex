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
# or run it without installing:
uvx --from git+https://github.com/DjodyKort/zyxel-ex zyx status
```

## Credentials

Pick one; the first that has a value wins:

1. flags: `--host`, `--user`, `--password`, `--pin`, `--sha512`
2. environment: `ZY_HOST`, `ZY_USER`, `ZY_PASS`, `ZY_PIN`, `ZY_SHA512`
3. a `.env` file with those same keys: `--env-file PATH` / `ZY_ENV_FILE`, else
   `./.env`, else `~/.config/zyxel-ex/.env` (see `.env.example`)
4. the OS keyring (Windows Credential Manager, macOS Keychain, Secret Service),
   filled by `zyx auth save`
5. a password prompt

```bash
zyx auth save              # checks the password, stores it + the gateway's TLS pin
zyx auth status            # where the password and pin come from
zyx auth forget            # remove them again
zyx cert                   # the gateway's certificate fingerprint (for --pin / ZY_PIN)
```

## Use

```bash
zyx status                 # model / firmware / uptime
zyx hosts [--wifi]         # connected devices (signal, OS) — device tracking
zyx dhcp                   # static DHCP reservations (with device names)
zyx wifi list              # SSIDs / bands / security
zyx wifi disable 2         # toggle an SSID (2.4G/5G/guest)
zyx nat list               # port-forward rules, incl. which WAN each listens on
zyx nat add --name "My app" --to 192.168.1.21 --ext 8443 --int 443 --proto TCP
zyx nat edit 5 --proto TCP --int 22   # change fields in place
zyx nat edit 5 --any-wan   # repair a rule whose WAN shows "none"
zyx nat disable 5          # enable / disable a rule
zyx nat rm 5 [-y]          # delete (asks first; indexes shift after a delete)
zyx firewall               # firewall ACLs
zyx wan                    # public IP / gateway / DNS
zyx watch [--ntfy URL]     # live device join/leave tracking
zyx metrics [--serve]      # Prometheus exporter (print once or serve /metrics on 127.0.0.1)
zyx reboot                 # reboot the gateway
zyx get <oid>              # raw decrypted JSON for any OID
zyx set <oid> '{…}'        # POST a raw record (advanced)
zyx oids                   # commonly-used OIDs

# offline — no gateway needed:
zyx backup decode dump.conf [--secrets]   # decode a config backup → XML / creds
```

Writes are **model-agnostic**: toggles/edits read the device's own record and
write it back with only your change applied, so they work across firmware
variants (which use different field names) without special-casing.

As a library:

```python
from zyxel_ex import ZyxelClient

with ZyxelClient("192.168.1.1", "admin", "…", pin="d1c8f5…") as z:
    for rule in z.dal_get("nat")["Object"]:
        print(rule["Description"], rule["ExternalPortStart"])
```

## Security

- The gateway's HTTPS certificate is self-signed, so CA verification is off. Without
  a pin, anyone on the LAN who can intercept traffic can hand out their own RSA key
  at login and read the admin password. **Pin the certificate**: `zyx auth save` does
  it on first use (like SSH's `known_hosts`), or pass `--pin` / `ZY_PIN`. With a pin,
  every response is checked, and a mismatch stops before the password is sent. After
  a firmware update or factory reset the certificate may change: check, then re-pin.
- Prefer the keyring over `--password` (shell history, process list) and over a
  `.env` (plaintext on disk; it is in `.gitignore` here, keep it that way).
- `metrics --serve` has no authentication and lists every device's name, MAC and IP.
  It binds to `127.0.0.1` unless you pass `--bind`.

## Compatibility

Built and live-tested against the **EX5601-T1** (Odido NL, OPAL_2.0 firmware).
The DAL handshake is shared across the OPAL EX/AX/VMG/DX families, so other
models should work — reports welcome. If your firmware wants a hashed password,
add `--sha512`.

| Model | Status |
|---|---|
| EX5601-T1 | ✅ verified (status, hosts, nat CRUD + edit, wifi, dhcp, TLS pin, keyring) |
| other EX/AX/VMG/DX (OPAL) | 🧪 should work — please report |

## Status

v0.4 — TLS pinning, keyring and `.env` credentials, `nat edit` / safer `nat rm` /
WAN binding in `nat list` (and `nat add` no longer creates rules bound to no WAN),
clean error messages, a `watch` and `metrics` that survive gateway reboots.

v0.3 — model-agnostic client + lazy login; commands for
status/info/reboot/hosts/nat (CRUD)/wifi/dhcp/firewall/wan/watch/metrics +
raw get/set; a self-contained `.conf` **backup decoder** (ported LZW, no deps);
GitHub Actions CI. Built to grow — each capability is a small command over a
`dal_*` call.

Tests run the real client and CLI against an in-memory fake gateway
(`tests/fake_gateway.py`) that does the actual RSA+AES handshake; nothing is mocked
or patched.

Roadmap: `zyx backup pull` (auto-download) · an async client for
HA/Ansible integrations · more model coverage.

## License

MIT
