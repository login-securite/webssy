"""
Data models for webssy
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

from webssy.utils.port_lists import MEDIUM_PORT_LIST


class Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"


class TargetSource(Enum):
    FILE = "file"
    NMAP = "nmap"


@dataclass
class Target:
    """Target to scan"""

    host: str
    port: int
    protocol: Protocol
    source: TargetSource = TargetSource.FILE
    original_line: Optional[str] = None
    discovered_from: Optional[str] = None

    def get_url(self) -> str:
        """Get full URL for this target"""
        return f"{self.protocol.value}://{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.get_url()


@dataclass
class ScanResult:
    """Result of scanning a target"""

    target: Target
    success: bool
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    screenshot_path: Optional[Path] = None
    page_title: Optional[str] = None
    error: Optional[str] = None
    duration_ms: int = 0
    protocol_used: Optional[Protocol] = None

    def __str__(self) -> str:
        if self.success:
            return f"[OK] {self.final_url} [{self.status_code}] - {self.page_title or 'No title'}"
        return f"[FAIL] {self.target} - {self.error}"


@dataclass
class Config:
    """Global configuration"""

    input_file: Optional[Path] = None
    nmap_file: Optional[Path] = None
    output_dir: Path = field(default_factory=lambda: Path("./webssy"))
    ports: List[int] = field(default_factory=lambda: list(MEDIUM_PORT_LIST))
    threads: int = 50
    timeout: int = 3
    screenshot_width: int = 1280
    screenshot_height: int = 1024
    follow_redirects: bool = True
    ignore_https_errors: bool = True
    certif_discovery: bool = False

    def validate(self) -> None:
        """Validate configuration"""
        if not self.input_file and not self.nmap_file:
            raise ValueError("Either input_file or nmap_file must be provided")

        if self.input_file and not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {self.input_file}")

        if self.nmap_file and not self.nmap_file.exists():
            raise FileNotFoundError(f"Nmap file not found: {self.nmap_file}")

        if self.threads < 1:
            raise ValueError("threads must be >= 1")

        if self.timeout < 1:
            raise ValueError("timeout must be >= 1")
