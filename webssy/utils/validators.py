"""
Input validation utilities
"""
import ipaddress
import re


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if string is a valid IP address

    Args:
        ip_str: String to validate

    Returns:
        True if valid IP
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """
    Check if string is a valid CIDR notation

    Args:
        cidr_str: String to validate

    Returns:
        True if valid CIDR
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """
    Check if string is a valid hostname

    Args:
        hostname: String to validate

    Returns:
        True if valid hostname
    """
    if len(hostname) > 255:
        return False

    # Allow alphanumeric, hyphens, dots
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, hostname))
