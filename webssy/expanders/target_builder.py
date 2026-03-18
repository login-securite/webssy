"""
Build Target objects from parsed input
"""

from typing import List, Optional

from webssy.models import Protocol, Target, TargetSource


class TargetBuilder:
    @staticmethod
    def build_from_host(
        host: str,
        ports: List[int],
        source: TargetSource = TargetSource.FILE,
        original_line: Optional[str] = None,
    ) -> List[Target]:
        """
        Build targets from host (IP or hostname)

        Args:
            host: IP address or hostname
            ports: List of ports to test
            source: Source of target
            original_line: Original input line

        Returns:
            List of Target objects (2 per port: HTTP and HTTPS)
        """
        targets = []
        for port in ports:
            targets.extend(
                TargetBuilder._create_dual_protocol_targets(
                    host=host, port=port, source=source, original_line=original_line
                )
            )
        return targets

    @staticmethod
    def build_from_url(
        protocol: str,
        host: str,
        port: Optional[int] = None,
        source: TargetSource = TargetSource.FILE,
        original_line: Optional[str] = None,
    ) -> Target:
        """
        Build target from URL

        Args:
            protocol: Protocol (http/https)
            host: Host (IP or hostname)
            port: Port number (default based on protocol)
            source: Source of target
            original_line: Original input line

        Returns:
            Target object
        """
        if port is None:
            port = 443 if protocol == "https" else 80

        protocol_enum = Protocol.HTTPS if protocol == "https" else Protocol.HTTP

        return Target(
            host=host,
            port=port,
            protocol=protocol_enum,
            source=source,
            original_line=original_line,
        )

    @staticmethod
    def _create_dual_protocol_targets(
        host: str, port: int, source: TargetSource, original_line: Optional[str]
    ) -> List[Target]:
        """Create both HTTP and HTTPS targets for a host:port pair."""
        return [
            Target(
                host=host,
                port=port,
                protocol=Protocol.HTTP,
                source=source,
                original_line=original_line,
            ),
            Target(
                host=host,
                port=port,
                protocol=Protocol.HTTPS,
                source=source,
                original_line=original_line,
            ),
        ]
