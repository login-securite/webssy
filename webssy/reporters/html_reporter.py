"""
HTML report generation using Jinja2
"""
import logging
from pathlib import Path
from datetime import datetime
from typing import List
from jinja2 import Template

from webssy.models import ScanResult, Config
from webssy.reporters.grouper import ResultGrouper


class HtmlReporter:
    def __init__(self, config: Config, output_dir: Path):
        """
        Initialize HTML reporter

        Args:
            config: Global configuration
            output_dir: Output directory for report
        """
        self.config = config
        self.output_dir = output_dir
        self.logger = logging.getLogger("webssy")

    def generate(self, scan_results: List[ScanResult], total_targets: int, alive_count: int) -> Path:
        """
        Generate HTML report

        Args:
            scan_results: List of scan results
            total_targets: Total number of targets scanned
            alive_count: Number of alive targets

        Returns:
            Path to generated HTML report
        """
        report_path = self.output_dir / "report.html"

        # Calculate statistics
        screenshot_count = sum(1 for r in scan_results if r.success and r.screenshot_path)
        failed_count = sum(1 for r in scan_results if not r.success)

        # Group results by similarity
        grouper = ResultGrouper(use_visual_similarity=True)
        grouped_results = grouper.group_results(scan_results)

        # Calculate total duration
        total_duration_ms = sum(r.duration_ms for r in scan_results)
        total_duration_s = total_duration_ms / 1000

        # Render template
        template = Template(self._get_template())
        html = template.render(
            title="Webssy Scan Report",
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_targets=total_targets,
            alive_count=alive_count,
            screenshot_count=screenshot_count,
            failed_count=failed_count,
            total_duration_s=total_duration_s,
            grouped_results=grouped_results,
            group_count=len(grouped_results),
            config=self.config,
        )

        # Write report
        report_path.write_text(html, encoding='utf-8')

        self.logger.info(f"HTML report generated: {report_path}")

        return report_path

    def _get_template(self) -> str:
        """Get HTML template from file"""
        template_path = Path(__file__).parent / "template.html"
        return template_path.read_text(encoding='utf-8')
