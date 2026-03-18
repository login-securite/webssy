"""
CLI interface using Typer
"""

import asyncio
from pathlib import Path
from typing import Annotated, List, Optional

import typer

from webssy import __version__
from webssy.models import Config, Target
from webssy.parsers.input_parser import InputParser
from webssy.parsers.nmap_parser import NmapParser
from webssy.reporters.html_reporter import HtmlReporter
from webssy.scanner.orchestrator import ScanOrchestrator
from webssy.utils.logger import print_error, print_status, setup_logger
from webssy.utils.output import create_output_structure
from webssy.utils.port_lists import MEDIUM_PORT_LIST, PORT_ALIASES, parse_ports


def _ports_help() -> str:
    lines = ["Ports to scan (default: medium):"]
    for alias, port_list in PORT_ALIASES.items():
        lines.append(f"  {alias}: {', '.join(map(str, port_list))}")
    lines.append("Or a comma-separated list: 80,443,8080")
    return "\n".join(lines)


app = typer.Typer(
    name="webssy",
    help="Web screenshot tool for pentesting - capture screenshots of web interfaces",
    add_completion=False,
)


def version_callback(value: bool):
    """Print version and exit"""
    if value:
        print_status(f"webssy version {__version__}")
        raise typer.Exit()


@app.command()
def main(
    input_file: Annotated[
        Optional[str],
        typer.Argument(
            help="Input file with targets (IPs, CIDRs, ranges, URLs, hostnames)"
        ),
    ] = None,
    nmap: Annotated[
        Optional[str], typer.Option("--nmap", "-n", help="Nmap XML file to parse")
    ] = None,
    ports: Annotated[
        Optional[str],
        typer.Option(
            "--ports",
            "-p",
            help=_ports_help(),
        ),
    ] = None,
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output directory for results")
    ] = "./webssy",
    threads: Annotated[
        int, typer.Option("--threads", "-t", help="Number of concurrent threads", min=1)
    ] = 50,
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout", help="Timeout for screenshots in seconds", min=1, max=120
        ),
    ] = 3,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose output")
    ] = False,
    certif: Annotated[
        bool,
        typer.Option(
            "--certif",
            help="Enable SSL certificate discovery (extract and test certificate hostnames)",
        ),
    ] = False,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
):
    """
    Webssy - Web screenshot tool for pentesting

    Examples:

      webssy targets.txt

      webssy targets.txt --ports small

      webssy targets.txt --ports 80,443,8080

      webssy targets.txt --ports xlarge --certif

      webssy --nmap scan.xml

      webssy targets.txt --output ./results --threads 20
    """
    logger = setup_logger(verbose)

    # Validate inputs
    if not input_file and not nmap:
        print_error("Either input file or --nmap must be provided")
        raise typer.Exit(1)

    # Parse ports
    ports_list = None
    if ports:
        try:
            ports_list = parse_ports(ports)
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)

    # Create and validate config
    try:
        config = Config(
            input_file=Path(input_file) if input_file else None,
            nmap_file=Path(nmap) if nmap else None,
            output_dir=Path(output),
            ports=ports_list or MEDIUM_PORT_LIST,
            threads=threads,
            timeout=timeout,
            certif_discovery=certif,
        )
        config.validate()
    except (ValueError, FileNotFoundError) as e:
        print_error(str(e))
        raise typer.Exit(1)

    # Parse targets
    targets = _parse_targets(config)
    if not targets:
        print_error("No targets found")
        raise typer.Exit(1)

    logger.info(f"Generated {len(targets)} targets to probe")

    # Sort targets by host for intelligent batching (reuse TCP connections)
    targets.sort(key=lambda t: (t.host, t.protocol.value, t.port))

    # Create output structure
    run_dir, screenshots_dir = create_output_structure(config.output_dir)

    # Run async scanning
    results = asyncio.run(ScanOrchestrator(config, targets, screenshots_dir).run())

    # Generate HTML report
    if results:
        reporter = HtmlReporter(config, run_dir)
        alive_count = sum(1 for r in results if r.success or r.status_code)
        report_path = reporter.generate(results, len(targets), alive_count)
        print_status(f"\nHTML report generated: {report_path}")


def _parse_targets(config: Config) -> List[Target]:
    """Parse targets from config's input file or nmap file."""
    try:
        if config.input_file:
            input_parser = InputParser(ports=config.ports)
            return input_parser.parse_file(config.input_file)
        if config.nmap_file:
            nmap_parser = NmapParser()
            return nmap_parser.parse_file(config.nmap_file)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)
    return []


if __name__ == "__main__":
    app()
