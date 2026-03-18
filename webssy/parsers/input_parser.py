"""
Parse mixed input file with various formats
"""

import logging
from pathlib import Path
from typing import List

from webssy.expanders.ip_expander import IPExpander
from webssy.expanders.target_builder import TargetBuilder
from webssy.models import Target, TargetSource
from webssy.parsers.line_detector import LineDetector, LineType


class InputParser:
    def __init__(self, ports: List[int]):
        """
        Initialize parser

        Args:
            ports: List of ports to test for non-URL entries
        """
        self.ports = ports
        self.logger = logging.getLogger("webssy")

    def parse_file(self, file_path: Path) -> List[Target]:
        """
        Parse input file and return targets

        Args:
            file_path: Path to input file

        Returns:
            List of Target objects
        """
        targets = []
        errors = 0

        self.logger.info(f"Parsing input file: {file_path}")

        with open(file_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    line_targets = self._parse_line(line)
                    targets.extend(line_targets)

                except ValueError as e:
                    self.logger.warning(f"Line {line_num}: {e} - '{line}'")
                    errors += 1
                except Exception as e:
                    self.logger.error(f"Line {line_num}: Unexpected error: {e}")
                    errors += 1

        self.logger.info(f"Parsed {len(targets)} targets ({errors} errors)")

        return targets

    def _parse_line(self, line: str) -> List[Target]:
        """
        Parse a single line and return targets

        Args:
            line: Line to parse

        Returns:
            List of Target objects

        Raises:
            ValueError: If line is invalid
        """
        line_type, match = LineDetector.detect(line)

        if line_type in (LineType.COMMENT, LineType.EMPTY):
            return []

        if line_type == LineType.INVALID or match is None:
            raise ValueError("Invalid format")

        if line_type == LineType.URL:
            protocol, host, port = LineDetector.parse_url(match)
            target = TargetBuilder.build_from_url(
                protocol=protocol,
                host=host,
                port=port,
                source=TargetSource.FILE,
                original_line=line,
            )
            return [target]

        if line_type == LineType.HOST_PORT:
            host, port = LineDetector.parse_host_port(match)
            # Create both HTTP and HTTPS targets for this host:port
            return TargetBuilder._create_dual_protocol_targets(
                host=host, port=port, source=TargetSource.FILE, original_line=line
            )

        if line_type in (LineType.IP, LineType.HOSTNAME):
            return TargetBuilder.build_from_host(
                host=line,
                ports=self.ports,
                source=TargetSource.FILE,
                original_line=line,
            )

        if line_type == LineType.CIDR:
            try:
                ips = IPExpander.expand_cidr(line)
            except ValueError as e:
                raise ValueError(f"CIDR expansion failed: {e}")
            self.logger.debug(f"CIDR {line} expanded to {len(ips)} IPs")
            return self._expand_ips_to_targets(ips, line)

        if line_type == LineType.RANGE:
            base_ip, start, end = LineDetector.parse_range(match, line)
            try:
                ips = IPExpander.expand_range(base_ip, start, end)
            except ValueError as e:
                raise ValueError(f"Range expansion failed: {e}")
            self.logger.debug(f"Range {line} expanded to {len(ips)} IPs")
            return self._expand_ips_to_targets(ips, line)

        raise ValueError(f"Unhandled line type: {line_type}")

    def _expand_ips_to_targets(self, ips: List[str], original_line: str) -> List[Target]:
        """Build targets from a list of expanded IPs."""
        targets = []
        for ip in ips:
            targets.extend(
                TargetBuilder.build_from_host(
                    host=ip,
                    ports=self.ports,
                    source=TargetSource.FILE,
                    original_line=original_line,
                )
            )
        return targets
