"""
Webssy - Web screenshot tool for pentesting
"""

__version__ = "0.1.0"
__author__ = "Pixis"

from webssy.models import Target, ScanResult, Config, Protocol, TargetSource

__all__ = [
    "Target",
    "ScanResult",
    "Config",
    "Protocol",
    "TargetSource",
]
