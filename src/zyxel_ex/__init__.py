"""zyxel-ex — scriptable client + CLI for Zyxel EX/AX (OPAL) home gateways."""

from .client import ZyxelClient, ZyxelError

__all__ = ["ZyxelClient", "ZyxelError"]
__version__ = "0.1.0"
