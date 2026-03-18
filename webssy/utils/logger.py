"""
Logging and output utilities using Rich
"""
import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Setup logger with Rich handler

    Args:
        verbose: Enable verbose logging

    Returns:
        Configured logger
    """
    level = logging.INFO if verbose else logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                tracebacks_show_locals=verbose,
                show_time=False,
                show_path=False,
            )
        ],
    )

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("playwright").setLevel(logging.WARNING)

    logger = logging.getLogger("webssy")
    logger.setLevel(level)

    return logger


def print_error(message: str) -> None:
    """Print an error message to the user."""
    console.print(f"[red]Error:[/red] {message}")


def print_status(message: str) -> None:
    """Print a status message to the user."""
    console.print(message)


def print_success(message: str) -> None:
    """Print a success message to the user."""
    console.print(f"[green]{message}[/green]")
