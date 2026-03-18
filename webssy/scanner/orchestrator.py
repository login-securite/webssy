"""
Scan orchestrator: coordinates HTTP probing and screenshot capture pipeline
"""

import asyncio
import logging
from collections import defaultdict
from pathlib import Path
from typing import List

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from webssy.models import Config, Protocol, ScanResult, Target, TargetSource
from webssy.scanner.http_prober import HttpProber
from webssy.scanner.screenshot_engine import ScreenshotEngine
from webssy.scanner.worker_pool import WorkerPool
from webssy.utils.logger import console, print_status, print_success


class ScanOrchestrator:
    """Coordinates the probe -> screenshot pipeline."""

    def __init__(self, config: Config, targets: List[Target], screenshots_dir: Path):
        self.config = config
        self.targets = targets
        self.screenshots_dir = screenshots_dir
        self.logger = logging.getLogger("webssy")

        # Shared state between producer and consumer
        self._alive_queue: asyncio.Queue = asyncio.Queue()
        self._results: List[ScanResult] = []
        self._probing_done = asyncio.Event()
        self._screenshot_count = 0

        # Certificate discovery state
        self._tested_targets: set = set()
        self._new_targets_queue: asyncio.Queue = asyncio.Queue()
        self._discovered_count = 0

    async def run(self) -> List[ScanResult]:
        """Run the full probe + screenshot pipeline. Returns scan results."""
        # Initialize tested targets set
        for target in self.targets:
            self._tested_targets.add(
                (target.host, target.port, target.protocol.value)
            )

        alive_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            self._progress = progress
            self._probe_task = progress.add_task(
                "Probing...", total=len(self.targets)
            )

            worker_results = await asyncio.gather(
                self._probe_worker(), self._screenshot_worker()
            )
            alive_count, discovered_count = worker_results[0]

        if self.config.certif_discovery and discovered_count > 0:
            print_success(
                f"\nDiscovered {discovered_count} new targets from SSL certificates"
            )

        if alive_count == 0:
            return []

        return self._results

    # -- Probing (producer) ---------------------------------------------------

    async def _probe_worker(self):
        """Probe all targets and feed alive ones to the screenshot queue."""
        alive_count = 0

        def on_probe_complete(result):
            nonlocal alive_count
            target, success, status_code, final_url, cert_hostnames = result
            self._progress.update(self._probe_task, advance=1)

            if success:
                alive_count += 1
                self._alive_queue.put_nowait((target, status_code, final_url))

            if self.config.certif_discovery and cert_hostnames:
                self._handle_cert_discovery(target, cert_hostnames)

        work_units = self._build_work_units(self.targets)

        async def process_work_unit(unit_targets):
            prober = HttpProber(
                timeout=self.config.timeout,
                follow_redirects=True,
                certif_discovery=self.config.certif_discovery,
            )
            try:
                for target in unit_targets:
                    if target.source == TargetSource.NMAP:
                        # Port already confirmed open by nmap, skip HTTP probe
                        on_probe_complete((target, True, None, target.get_url(), []))
                    else:
                        result = await prober.probe(target)
                        on_probe_complete(result)
            finally:
                await prober.close()

        pool = WorkerPool(max_workers=self.config.threads)
        await pool.map(process_work_unit, work_units)

        # Probe newly discovered targets from certificates
        await self._probe_discovered_targets(process_work_unit)

        self._probing_done.set()
        return alive_count, self._discovered_count

    def _handle_cert_discovery(self, target: Target, cert_hostnames: List[str]):
        """Queue new targets discovered via SSL certificates."""
        for hostname in cert_hostnames:
            if hostname.lower() == target.host.lower():
                continue

            new_target_key = (hostname, target.port, Protocol.HTTPS.value)
            if new_target_key not in self._tested_targets:
                self._tested_targets.add(new_target_key)
                new_target = Target(
                    host=hostname,
                    port=target.port,
                    protocol=Protocol.HTTPS,
                    source=TargetSource.FILE,
                    original_line=None,
                    discovered_from=f"{target.host}:{target.port}",
                )
                self._new_targets_queue.put_nowait(new_target)
                self._discovered_count += 1

    async def _probe_discovered_targets(self, process_work_unit):
        """Drain the discovered-targets queue and probe them."""
        while not self._new_targets_queue.empty():
            batch = []
            while not self._new_targets_queue.empty() and len(batch) < 50:
                try:
                    batch.append(self._new_targets_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            if batch:
                self._progress.update(
                    self._probe_task,
                    total=self._progress.tasks[0].total + len(batch),
                )
                discovered_work_units = self._build_work_units(batch)
                pool = WorkerPool(max_workers=self.config.threads)
                await pool.map(process_work_unit, discovered_work_units)

    def _build_work_units(self, targets: List[Target]) -> List[List[Target]]:
        """
        Group targets into work units for parallel probing.

        Keeps targets of the same host together for HTTP connection reuse,
        while splitting large groups to maximize thread utilisation.
        """
        hosts_map: dict[str, list[Target]] = defaultdict(list)
        for target in targets:
            hosts_map[target.host].append(target)

        num_hosts = len(hosts_map)
        total_targets = sum(len(t) for t in hosts_map.values())
        target_work_units = min(self.config.threads * 2, total_targets)

        work_units: List[List[Target]] = []

        if num_hosts >= self.config.threads:
            for host_targets in hosts_map.values():
                work_units.append(host_targets)
        else:
            ideal_chunk_size = max(2, total_targets // target_work_units)
            for host_targets in hosts_map.values():
                if len(host_targets) <= ideal_chunk_size:
                    work_units.append(host_targets)
                else:
                    for i in range(0, len(host_targets), ideal_chunk_size):
                        work_units.append(host_targets[i : i + ideal_chunk_size])

        return work_units

    # -- Screenshots (consumer) -----------------------------------------------

    async def _screenshot_worker(self):
        """Consume alive targets from the queue and capture screenshots."""
        async with ScreenshotEngine(self.config, self.screenshots_dir) as engine:
            while True:
                try:
                    target, status_code, final_url = await asyncio.wait_for(
                        self._alive_queue.get(), timeout=0.5
                    )

                    result = await engine.capture(target, status_code, final_url)
                    self._results.append(result)
                    self._screenshot_count += 1

                    display = result.final_url if result.success else str(result.target)
                    print_status(f"[{self._screenshot_count}] {display}")

                except asyncio.TimeoutError:
                    if self._probing_done.is_set() and self._alive_queue.empty():
                        break
