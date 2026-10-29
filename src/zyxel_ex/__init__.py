"""zyxel-ex — scriptable client + CLI for Zyxel EX/AX (OPAL) home gateways."""

from .client import PinMismatchError, ZyxelClient, ZyxelError

__all__ = ["PinMismatchError", "ZyxelClient", "ZyxelError"]
__version__ = "0.4.0"
