"""zyxel-ex — scriptable client + CLI for Zyxel EX/AX (OPAL) home gateways."""

from .client import PinMismatchError, ZyxelClient, ZyxelError, cert_fingerprint

__all__ = ["PinMismatchError", "ZyxelClient", "ZyxelError", "cert_fingerprint"]
__version__ = "0.3.0"
