"""HTTP client for the Zyxel OPAL DAL API (login + encrypted DAL read/write)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
from types import TracebackType
from typing import Any

import httpx

from . import crypto

DEFAULT_HOST = "192.168.1.1"


class ZyxelError(RuntimeError):
    """A DAL call returned a non-success result, or the transport failed."""


class PinMismatchError(ZyxelError):
    """The gateway's TLS certificate does not match the pinned fingerprint."""


def normalize_fingerprint(fp: str) -> str:
    """Lower-case hex without separators, so ``AB:CD:…`` and ``abcd…`` compare equal."""
    return fp.replace(":", "").replace(" ", "").lower()


def cert_fingerprint(host: str, port: int = 443, *, timeout: float = 10.0) -> str:
    """SHA-256 fingerprint (hex) of the gateway's TLS certificate, for pinning."""
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


class ZyxelClient:
    """Talks to a Zyxel EX/AX gateway's web API.

    Usage:
        with ZyxelClient("192.168.1.1", "admin", "secret") as z:
            print(z.dal_get("nat")["Object"])
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        username: str = "admin",
        password: str = "",
        *,
        verify: bool = False,
        pin: str | None = None,
        timeout: float = 20.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.base = f"https://{host}"
        self.aes_key: bytes = b""
        self.session_key: str = ""
        self.login_sha512: bool = False  # default for login(); set by the CLI
        # SHA-256 of the gateway's cert. The cert is self-signed, so CA verification is
        # useless; a pin is what stops a LAN man-in-the-middle from handing us its own
        # RSA key at login and reading the password.
        self.pin: str | None = normalize_fingerprint(pin) if pin else None
        self._device_info: dict[str, Any] | None = None
        # verify=False: these gateways ship a self-signed cert on the LAN.
        # transport is injectable for tests (a fake gateway).
        self._http = httpx.Client(base_url=self.base, verify=verify, timeout=timeout, transport=transport)

    # -- lifecycle ----------------------------------------------------------

    def __enter__(self) -> ZyxelClient:
        self.login()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        try:
            if self.session_key:
                self._http.get(f"/cgi-bin/UserLogout?sessionkey={self.session_key}")
        except httpx.HTTPError:
            pass
        self._http.close()

    # -- auth ---------------------------------------------------------------

    def login(self, *, sha512: bool | None = None) -> dict[str, Any]:
        """Perform the RSA+AES handshake and establish a session.

        Some firmware variants expect the password SHA-512-hashed rather than
        base64-encoded; set ``sha512=True`` for those. Left unset, it follows
        ``login_sha512``, so a session refresh logs in the same way as the first login.
        """
        if sha512 is None:
            sha512 = self.login_sha512
        rsa_key = self._get_json("/getRSAPublickKey")["RSAPublicKey"]
        self.aes_key = crypto.gen_key()
        iv = crypto.gen_iv()
        passwd = (
            hashlib.sha512(self.password.encode()).hexdigest()
            if sha512
            else base64.b64encode(self.password.encode()).decode()
        )
        payload = json.dumps(
            {
                "Input_Account": self.username,
                "Input_Passwd": passwd,
                "currLang": "en",
                "RememberPassword": 0,
                "SHA512_password": sha512,
            }
        )
        body = json.dumps(
            {
                "content": crypto.aes_encrypt(payload, self.aes_key, iv),
                "key": crypto.rsa_encrypt(base64.b64encode(self.aes_key).decode(), rsa_key),
                "iv": base64.b64encode(iv).decode(),
            }
        )
        resp = self._post_raw("/UserLogin", body, headers={"Content-Type": "application/json"})
        data = self._decrypt(resp)
        if data.get("result") not in (None, "ZCFG_SUCCESS") and "sessionkey" not in data:
            raise ZyxelError(f"login failed: {data.get('result') or data}")
        self.session_key = data.get("sessionkey", "")
        if not self.session_key:
            raise ZyxelError("login returned no sessionkey (bad credentials or locked account)")
        return data

    # -- DAL primitives -----------------------------------------------------

    def dal_get(self, oid: str) -> dict[str, Any]:
        """Read a config/status object."""
        return self._require_ok(self._decrypt(self._get_raw(f"/cgi-bin/DAL?oid={oid}{self._sk()}")), oid)

    def dal_post(self, oid: str, data: dict[str, Any]) -> dict[str, Any]:
        """Create/set a record (e.g. add a NAT rule). `data` is the record object."""
        resp = self._post_raw(
            f"/cgi-bin/DAL?oid={oid}{self._sk()}",
            self._encrypt_body(data),
            headers={"Content-Type": "application/x-www-form-urlencoded", "CSRFToken": self.session_key},
        )
        return self._require_ok(self._decrypt(resp), oid)

    def dal_put(self, oid: str, index: int, data: dict[str, Any]) -> dict[str, Any]:
        """Modify record `index` of `oid`."""
        resp = self._request_raw(
            "PUT",
            f"/cgi-bin/DAL?oid={oid}{self._sk()}&Index={index}",
            self._encrypt_body(data),
            headers={"Content-Type": "application/x-www-form-urlencoded", "CSRFToken": self.session_key},
        )
        return self._require_ok(self._decrypt(resp), oid)

    def dal_delete(self, oid: str, index: int) -> dict[str, Any]:
        """Delete record `index` of `oid`."""
        resp = self._request_raw(
            "DELETE",
            f"/cgi-bin/DAL?oid={oid}{self._sk()}&Index={index}",
            self._encrypt_body({}),
            headers={"Content-Type": "application/x-www-form-urlencoded", "CSRFToken": self.session_key},
        )
        return self._require_ok(self._decrypt(resp), oid)

    # -- convenience --------------------------------------------------------

    def dal_list(self, oid: str) -> list[dict[str, Any]]:
        """The ``Object`` array of a DAL read (the common list-of-records shape)."""
        objects: list[dict[str, Any]] = self.dal_get(oid).get("Object", [])
        return objects

    def update_item(self, oid: str, index: int, changes: dict[str, Any]) -> dict[str, Any]:
        """Read record ``index`` of ``oid``, apply ``changes``, write it back.

        Model-agnostic: it echoes the device's own record (whatever field names
        that firmware uses) with only ``changes`` overridden, so toggles/edits
        work across firmware variants without hardcoding the schema.
        """
        for item in self.dal_list(oid):
            if item.get("Index") == index:
                return self.dal_put(oid, index, {**item, **changes})
        raise ZyxelError(f"{oid}: no record with Index {index}")

    def device_info(self) -> dict[str, Any]:
        """The ``DeviceInfo`` block from ``status`` (model, firmware, serial, uptime)."""
        if self._device_info is None:
            self._device_info = next(
                (o["DeviceInfo"] for o in self.dal_list("status") if o.get("DeviceInfo")), {}
            )
        return self._device_info

    @property
    def model(self) -> str:
        return str(self.device_info().get("ModelName", ""))

    @property
    def firmware(self) -> str:
        return str(self.device_info().get("SoftwareVersion", ""))

    # -- internals ----------------------------------------------------------

    def _sk(self) -> str:
        return f"&sessionkey={self.session_key}" if self.session_key else ""

    def _encrypt_body(self, data: dict[str, Any]) -> str:
        iv = crypto.gen_iv()
        return json.dumps(
            {
                "content": crypto.aes_encrypt(json.dumps(data), self.aes_key, iv),
                "iv": base64.b64encode(iv).decode(),
            }
        )

    def _decrypt(self, raw: str) -> dict[str, Any]:
        obj: dict[str, Any] = json.loads(raw)
        if "content" in obj and "iv" in obj:
            plain: dict[str, Any] = json.loads(
                crypto.aes_decrypt(obj["content"], self.aes_key, base64.b64decode(obj["iv"]))
            )
            return plain
        return obj

    @staticmethod
    def _require_ok(data: dict[str, Any], oid: str) -> dict[str, Any]:
        result = data.get("result")
        if result not in (None, "ZCFG_SUCCESS"):
            raise ZyxelError(f"{oid}: {result} ({data.get('ReplyMsg', '')})")
        return data

    def _get_json(self, path: str) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(self._get_raw(path))
        return data

    def _get_raw(self, path: str) -> str:
        return self._request_raw("GET", path, None, None)

    def _post_raw(self, path: str, body: str, headers: dict[str, str]) -> str:
        return self._request_raw("POST", path, body, headers)

    def _request_raw(self, method: str, path: str, body: str | None, headers: dict[str, str] | None) -> str:
        try:
            r = self._http.request(method, path, content=body, headers=headers)
            if self.pin:
                self._check_pin(r)
            r.raise_for_status()
            return r.text
        except httpx.HTTPError as e:
            raise ZyxelError(f"{method} {path}: {e}") from e

    def _check_pin(self, response: httpx.Response) -> None:
        # Checked on every response; the first one (the RSA key fetch) carries no secret,
        # so a mismatch is caught before the password is ever sent.
        stream = response.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream else None
        der = ssl_object.getpeercert(True) if ssl_object else None
        if not der:
            raise PinMismatchError("a TLS pin is set but the gateway certificate could not be read")
        actual = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(actual, self.pin or ""):
            raise PinMismatchError(
                f"TLS certificate of {self.host} does not match the pin "
                f"(got {actual}). If the gateway's cert legitimately changed "
                "(firmware update, factory reset), re-pin it; otherwise do not log in."
            )
