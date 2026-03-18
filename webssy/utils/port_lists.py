"""
Port list aliases (inspired by Aquatone)
"""

SMALL_PORT_LIST = [80, 443]

MEDIUM_PORT_LIST = [80, 443, 8000, 8080, 8443]

LARGE_PORT_LIST = [
    80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001,
    8008, 8080, 8083, 8443, 8834, 8888
]

XLARGE_PORT_LIST = [
    80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311,
    2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567,
    4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396,
    7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088,
    8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333,
    8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080,
    9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092,
    20720, 28017
]

PORT_ALIASES = {
    "small": SMALL_PORT_LIST,
    "medium": MEDIUM_PORT_LIST,
    "large": LARGE_PORT_LIST,
    "xlarge": XLARGE_PORT_LIST,
}


def parse_ports(ports_arg: str) -> list[int]:
    """
    Parse port argument which can be either:
    - An alias: small, medium, large, xlarge
    - A comma-separated list of ports: 80,443,8080

    Args:
        ports_arg: Port argument string

    Returns:
        List of port numbers

    Raises:
        ValueError: If the argument is invalid
    """
    ports_arg = ports_arg.strip().lower()

    # Check if it's an alias
    if ports_arg in PORT_ALIASES:
        return PORT_ALIASES[ports_arg]

    # Parse as comma-separated port list
    try:
        ports = [int(p.strip()) for p in ports_arg.split(",")]
        # Validate port range
        for port in ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is out of valid range (1-65535)")
        return ports
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(
                f"Invalid ports argument: '{ports_arg}'. "
                f"Use an alias (small, medium, large, xlarge) or a comma-separated list of ports (80,443,8080)"
            )
        raise
