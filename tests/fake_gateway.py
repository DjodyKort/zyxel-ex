"""An in-memory Zyxel OPAL gateway to run the client and the CLI against.

It does what a real EX5601-T1 does on the wire: hands out an RSA public key,
unwraps the AES session key at login, AES-encrypts every reply, and serves DAL
records per OID. Writes are recorded decrypted, so tests can assert on exactly
what the client sent. Deleting a record renumbers the rest, like the real one.
It also presents a TLS certificate the way httpx exposes one, for pinning.

Behaviour the real gateway's firmware does not document (the reply to an expired
session) is modelled as a plain non-success result.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import httpx
from click.testing import CliRunner, Result
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from zyxel_ex import crypto
from zyxel_ex.cli import cli


class _SSLObject:
    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes:
        return self._der


class _TLSStream:
    """Stands in for httpcore's network stream in ``response.extensions``."""

    def __init__(self, der: bytes) -> None:
        self._ssl_object = _SSLObject(der)

    def get_extra_info(self, name: str) -> Any:
        return self._ssl_object if name == "ssl_object" else None


class FakeGateway:
    def __init__(
        self,
        *,
        user: str = "admin",
        password: str = "s3cret",
        sha512: bool = False,
        cert: bytes = b"fake gateway certificate",
        tables: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.user = user
        self.password = password
        self.sha512 = sha512
        self.cert = cert
        self.tables: dict[str, list[dict[str, Any]]] = tables or {}
        self.rejections: dict[str, str] = {}  # oid -> ReplyMsg returned for any write to it
        self.fail_reads = 0  # the next N DAL reads fail, like a gateway that is rebooting
        self.writes: list[tuple[str, str, dict[str, Any]]] = []  # (method, oid, decrypted record)
        self.login_attempts = 0
        self.logins = 0
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._aes_key = b""
        self._session = ""

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.cert).hexdigest()

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    @property
    def logged_in(self) -> bool:
        return bool(self._session)

    def expire_session(self) -> None:
        self._session = ""

    # -- wire ---------------------------------------------------------------

    def _reply(self, payload: dict[str, Any], *, encrypted: bool = True) -> httpx.Response:
        if encrypted:
            iv = crypto.gen_iv()
            payload = {
                "content": crypto.aes_encrypt(json.dumps(payload), self._aes_key, iv),
                "iv": base64.b64encode(iv).decode(),
            }
        return httpx.Response(
            200, text=json.dumps(payload), extensions={"network_stream": _TLSStream(self.cert)}
        )

    def _decrypt(self, body: bytes) -> dict[str, Any]:
        outer = json.loads(body)
        plain = crypto.aes_decrypt(outer["content"], self._aes_key, base64.b64decode(outer["iv"]))
        record: dict[str, Any] = json.loads(plain)
        return record

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/getRSAPublickKey":
            pem = (
                self._private_key.public_key()
                .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                .decode()
            )
            return self._reply({"RSAPublicKey": pem, "result": "ZCFG_SUCCESS"}, encrypted=False)
        if path == "/UserLogin":
            return self._login(json.loads(request.content))
        if path == "/cgi-bin/UserLogout":
            self._session = ""
            return self._reply({"result": "ZCFG_SUCCESS"}, encrypted=False)
        if path == "/cgi-bin/DAL":
            if not self._session or request.url.params.get("sessionkey") != self._session:
                return self._reply({"result": "ZCFG_INVALID_SESSION", "ReplyMsg": "not logged in"})
            return self._dal(request)
        return httpx.Response(404)

    def _login(self, body: dict[str, Any]) -> httpx.Response:
        self.login_attempts += 1
        wrapped = base64.b64decode(body["key"])
        self._aes_key = base64.b64decode(self._private_key.decrypt(wrapped, padding.PKCS1v15()))
        login = json.loads(crypto.aes_decrypt(body["content"], self._aes_key, base64.b64decode(body["iv"])))
        expected = (
            hashlib.sha512(self.password.encode()).hexdigest()
            if self.sha512
            else base64.b64encode(self.password.encode()).decode()
        )
        if login["Input_Account"] != self.user or login["Input_Passwd"] != expected:
            return self._reply({"result": "ZCFG_INVALID_ACCOUNT"})
        self.logins += 1
        self._session = f"SK-{self.logins}"
        return self._reply({"sessionkey": self._session, "result": "ZCFG_SUCCESS"})

    def _dal(self, request: httpx.Request) -> httpx.Response:
        oid = request.url.params["oid"]
        rows = self.tables.setdefault(oid, [])
        if request.method == "GET":
            if self.fail_reads:
                self.fail_reads -= 1
                return self._reply({"result": "ZCFG_INTERNAL_ERROR", "ReplyMsg": "busy"})
            return self._reply({"result": "ZCFG_SUCCESS", "Object": rows})
        record = self._decrypt(request.content)
        self.writes.append((request.method, oid, record))
        if oid in self.rejections:
            return self._reply({"result": "ZCFG_INVALID_PARAM_VALUE", "ReplyMsg": self.rejections[oid]})
        if request.method == "POST":
            rows.append({**record, "Index": len(rows) + 1})
        else:
            index = int(request.url.params["Index"])
            position = next(i for i, row in enumerate(rows) if row["Index"] == index)
            if request.method == "PUT":
                rows[position] = {**record, "Index": index}
            else:  # DELETE
                del rows[position]
                for i, row in enumerate(rows, start=1):
                    row["Index"] = i
        return self._reply({"result": "ZCFG_SUCCESS"})


def zyx(gateway: FakeGateway | None, *args: str, input: str | None = None) -> Result:
    """Run the CLI against ``gateway``, isolated from the developer's own ZY_* variables."""
    runner = CliRunner(env=dict.fromkeys(("ZY_HOST", "ZY_USER", "ZY_PASS", "ZY_PIN", "ZY_SHA512")))
    return runner.invoke(cli, list(args), obj=gateway.transport if gateway else None, input=input)
