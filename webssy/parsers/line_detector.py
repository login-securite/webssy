"""
Line type detection with regex patterns
"""
import re
from enum import Enum
from typing import Optional, Tuple

from webssy.utils.validators import is_valid_cidr, is_valid_hostname, is_valid_ip


class LineType(Enum):
    """Type of parsed line"""
    COMMENT = "comment"
    EMPTY = "empty"
    URL = "url"
    HOST_PORT = "host_port"  # IP:port or hostname:port
    CIDR = "cidr"
    RANGE = "range"
    IP = "ip"
    HOSTNAME = "hostname"
    INVALID = "invalid"


class LineDetector:
    """Detect line type using regex patterns"""

    # Patterns in order of priority
    PATTERNS = [
        (LineType.COMMENT, re.compile(r'^\s*#')),
        (LineType.EMPTY, re.compile(r'^\s*$')),
        (LineType.URL, re.compile(r'^(https?):\/\/([\w\-\.]+)(?::(\d+))?(?:\/.*)?$', re.IGNORECASE)),
        (LineType.HOST_PORT, re.compile(r'^([\w\-\.]+):(\d+)$')),  # IP:port or hostname:port
        (LineType.CIDR, re.compile(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$')),
        (LineType.RANGE, re.compile(r'^(\d{1,3}\.){3}(\d{1,3})-(\d{1,3})$')),
        (LineType.IP, re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')),
        (LineType.HOSTNAME, re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')),
    ]

    @classmethod
    def detect(cls, line: str) -> Tuple[LineType, Optional[re.Match]]:
        """
        Detect line type

        Args:
            line: Line to analyze

        Returns:
            Tuple of (LineType, regex match object)
        """
        line = line.strip()

        for line_type, pattern in cls.PATTERNS:
            match = pattern.match(line)
            if match:
                # Additional validation for IP and CIDR
                if line_type == LineType.IP and not is_valid_ip(line):
                    continue
                if line_type == LineType.CIDR and not is_valid_cidr(line):
                    continue
                if line_type == LineType.HOSTNAME and not is_valid_hostname(line):
                    continue

                return line_type, match

        return LineType.INVALID, None

    @staticmethod
    def parse_url(match: re.Match) -> Tuple[str, str, Optional[int]]:
        """
        Extract URL components from a URL match.

        Args:
            match: Regex match from detect() for a URL line

        Returns:
            Tuple of (protocol, host, port)
        """
        protocol = match.group(1).lower()
        host = match.group(2)
        port = int(match.group(3)) if match.group(3) else None
        return protocol, host, port

    @staticmethod
    def parse_range(match: re.Match, line: str) -> Tuple[str, int, int]:
        """
        Extract range components from a range match.

        Args:
            match: Regex match from detect() for a range line
            line: Original line string

        Returns:
            Tuple of (base_ip, start, end)
        """
        parts = line.split('-')
        base_ip = '.'.join(parts[0].split('.')[:-1])
        start = int(parts[0].split('.')[-1])
        end = int(parts[1])
        return base_ip, start, end

    @staticmethod
    def parse_host_port(match: re.Match) -> Tuple[str, int]:
        """
        Extract host and port from a host:port match.

        Args:
            match: Regex match from detect() for a host:port line

        Returns:
            Tuple of (host, port)
        """
        host = match.group(1)
        port = int(match.group(2))
        return host, port
