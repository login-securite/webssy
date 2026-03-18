"""
Output directory management
"""
from pathlib import Path
from datetime import datetime
from typing import Tuple


def create_output_structure(base_dir: Path) -> Tuple[Path, Path]:
    """
    Create output directory structure with timestamp

    Args:
        base_dir: Base output directory

    Returns:
        Tuple of (run_dir, screenshots_dir)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_dir / timestamp
    screenshots_dir = run_dir / "screenshots"

    run_dir.mkdir(parents=True, exist_ok=True)
    screenshots_dir.mkdir(exist_ok=True)

    return run_dir, screenshots_dir


def get_screenshot_filename(target_host: str, target_port: int, protocol: str) -> str:
    """
    Generate safe filename for screenshot

    Args:
        target_host: Host (IP or domain)
        target_port: Port number
        protocol: http or https

    Returns:
        Safe filename
    """
    # Replace special characters
    safe_host = target_host.replace(".", "_").replace(":", "_")
    return f"{safe_host}_{target_port}_{protocol}.png"
