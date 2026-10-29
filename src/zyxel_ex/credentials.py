"""Gateway credentials in the OS keyring (Windows Credential Manager, macOS Keychain,
Secret Service on Linux), so the password never has to live in env vars or shell history.

Next to the password it keeps the gateway's TLS fingerprint, recorded when the
credentials are saved (trust on first use, like SSH's known_hosts), so every later
session is pinned without extra configuration.

A machine without a keyring backend (a headless server) simply reports nothing
stored; ``ZY_PASS`` / ``ZY_PIN`` keep working there.
"""

from __future__ import annotations

import keyring
from keyring.errors import KeyringError

SERVICE = "zyxel-ex"


def _password_key(host: str, user: str) -> str:
    return f"{user}@{host}"


def _pin_key(host: str) -> str:
    return f"pin:{host}"


def _get(key: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, key)
    except KeyringError:
        return None


def password(host: str, user: str) -> str | None:
    return _get(_password_key(host, user))


def pin(host: str) -> str | None:
    return _get(_pin_key(host))


def save(host: str, user: str, password: str, fingerprint: str) -> None:
    """Store the password and the gateway's fingerprint. Raises ``KeyringError``."""
    keyring.set_password(SERVICE, _password_key(host, user), password)
    keyring.set_password(SERVICE, _pin_key(host), fingerprint)


def forget(host: str, user: str) -> bool:
    """Remove the stored password and pin; ``True`` if anything was removed."""
    removed = False
    for key in (_password_key(host, user), _pin_key(host)):
        try:
            keyring.delete_password(SERVICE, key)
            removed = True
        except KeyringError:  # not stored, or no backend
            pass
    return removed
