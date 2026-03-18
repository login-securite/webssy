"""
IP expansion for CIDR and ranges
"""
import ipaddress
from typing import List


class IPExpander:
    @staticmethod
    def expand_cidr(cidr: str, max_ips: int = 65536) -> List[str]:
        """
        Expand CIDR notation to individual IPs

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            max_ips: Maximum number of IPs to expand (safety limit)

        Returns:
            List of IP addresses as strings
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            # Safety check
            if network.num_addresses > max_ips:
                raise ValueError(
                    f"CIDR {cidr} would expand to {network.num_addresses} IPs "
                    f"(max: {max_ips}). Use smaller CIDR or increase limit."
                )

            return [str(ip) for ip in network.hosts()]

        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation '{cidr}': {e}")

    @staticmethod
    def expand_range(base_ip: str, start: int, end: int) -> List[str]:
        """
        Expand IP range to individual IPs

        Args:
            base_ip: Base IP without last octet (e.g., "192.168.1")
            start: Start of range (last octet)
            end: End of range (last octet)

        Returns:
            List of IP addresses as strings
        """
        if not (0 <= start <= 255 and 0 <= end <= 255):
            raise ValueError(f"Invalid range: {start}-{end} (must be 0-255)")

        if start > end:
            raise ValueError(f"Invalid range: start ({start}) > end ({end})")

        ips = []
        for i in range(start, end + 1):
            ip = f"{base_ip}.{i}"
            # Validate IP
            try:
                ipaddress.ip_address(ip)
                ips.append(ip)
            except ValueError:
                # Skip invalid IPs
                continue

        return ips
