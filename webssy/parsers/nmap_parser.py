"""
Parse Nmap XML output to extract targets
"""
import logging
from pathlib import Path
from typing import List, Optional

from lxml import etree

from webssy.expanders.target_builder import TargetBuilder
from webssy.models import Target, TargetSource


class NmapParser:
    def __init__(self):
        self.logger = logging.getLogger("webssy")

    def parse_file(self, file_path: Path) -> List[Target]:
        """
        Parse Nmap XML file and return targets

        Args:
            file_path: Path to Nmap XML file

        Returns:
            List of Target objects
        """
        targets = []
        hosts_count = 0
        ports_count = 0

        self.logger.info(f"Parsing Nmap XML file: {file_path}")

        try:
            tree = etree.parse(str(file_path))
            root = tree.getroot()

            for host in root.findall('.//host'):
                host_result = self._parse_host(host)
                if host_result is None:
                    continue

                host_target, host_targets, port_count = host_result
                hosts_count += 1
                ports_count += port_count
                targets.extend(host_targets)

            self.logger.info(
                f"Nmap XML parsing: {hosts_count} hosts, {ports_count} open ports, "
                f"{len(targets)} targets (HTTP+HTTPS)"
            )

        except etree.XMLSyntaxError as e:
            self.logger.error(f"Invalid XML file: {e}")
            raise ValueError(f"Invalid Nmap XML file: {e}")
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            raise ValueError(f"Failed to parse Nmap XML: {e}")

        return targets

    def _parse_host(self, host) -> Optional[tuple]:
        """
        Parse a single host element.

        Returns:
            Tuple of (host_address, targets, port_count) or None if host is not up
        """
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            return None

        host_addr = self._extract_address(host)
        if host_addr is None:
            return None

        hostname = self._extract_hostname(host)
        host_target = hostname or host_addr

        targets = []
        port_count = 0

        for port in host.findall('.//port'):
            port_target = self._parse_port(port, host_target)
            if port_target is not None:
                targets.extend(port_target)
                port_count += 1

        return host_target, targets, port_count

    @staticmethod
    def _extract_address(host) -> Optional[str]:
        """Extract IP address from host element."""
        address_elem = host.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host.find('address[@addrtype="ipv6"]')
        if address_elem is None:
            return None
        return address_elem.get('addr')

    @staticmethod
    def _extract_hostname(host) -> Optional[str]:
        """Extract best hostname from host element (prefer PTR records)."""
        hostnames = host.findall('.//hostname')
        if not hostnames:
            return None

        for hn in hostnames:
            if hn.get('type') == 'PTR':
                return hn.get('name')

        return hostnames[0].get('name')

    def _parse_port(self, port, host_target: str) -> Optional[List[Target]]:
        """
        Parse a single port element.

        Returns:
            List of targets or None if port should be skipped
        """
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            return None

        protocol_attr = port.get('protocol', 'tcp')
        if protocol_attr != 'tcp':
            return None

        port_id = int(port.get('portid'))

        service = port.find('service')
        if service is not None:
            service_name = service.get('name')
            service_tunnel = service.get('tunnel')
            if service_name:
                self.logger.debug(
                    f"Found {host_target}:{port_id} - service: {service_name}"
                    + (f" (tunnel: {service_tunnel})" if service_tunnel else "")
                )

        return TargetBuilder._create_dual_protocol_targets(
            host=host_target,
            port=port_id,
            source=TargetSource.NMAP,
            original_line=f"{host_target}:{port_id}",
        )
