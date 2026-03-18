"""
Group scan results by similarity
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

try:
    import imagehash
    from PIL import Image

    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False

from webssy.models import ScanResult


class ResultGrouper:
    """Group scan results by similarity"""

    def __init__(self, use_visual_similarity: bool = True):
        """
        Initialize result grouper

        Args:
            use_visual_similarity: Enable visual similarity detection
        """
        self.use_visual_similarity = use_visual_similarity and IMAGEHASH_AVAILABLE
        self.logger = logging.getLogger("webssy")

        if use_visual_similarity and not IMAGEHASH_AVAILABLE:
            self.logger.warning("imagehash not available, visual similarity disabled")

    def group_results(self, results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """
        Group results by similarity

        Args:
            results: List of scan results

        Returns:
            Dictionary of grouped results with group names as keys
        """
        groups: Dict[str, List[ScanResult]] = defaultdict(list)

        # Separate successful and failed results
        successful = [r for r in results if r.success and r.screenshot_path]
        failed = [r for r in results if not r.success or not r.screenshot_path]

        # Group successful results
        if self.use_visual_similarity:
            successful_groups = self._group_by_visual_similarity(successful)
        else:
            successful_groups = self._group_by_title_and_status(successful)

        # Group failed results by status code
        failed_groups = self._group_failures(failed)

        # Merge all groups
        groups.update(successful_groups)
        groups.update(failed_groups)

        # Sort results within each group by screenshot file size (largest first)
        for group_name in groups:
            groups[group_name] = self._sort_by_file_size(groups[group_name])

        # Sort groups by average screenshot size (largest first)
        sorted_groups = dict(
            sorted(
                groups.items(),
                key=lambda x: self._get_group_average_size(x[1]),
                reverse=True,
            )
        )

        self.logger.info(
            f"Grouped {len(results)} results into {len(sorted_groups)} groups"
        )

        return sorted_groups

    def _get_group_average_size(self, results: List[ScanResult]) -> float:
        """
        Calculate average screenshot file size for a group

        Args:
            results: List of results in the group

        Returns:
            Average file size in bytes (0 if no screenshots)
        """
        sizes = []
        for result in results:
            if result.screenshot_path and result.screenshot_path.exists():
                sizes.append(result.screenshot_path.stat().st_size)

        if not sizes:
            return 0.0

        return sum(sizes) / len(sizes)

    def _sort_by_file_size(self, results: List[ScanResult]) -> List[ScanResult]:
        """
        Sort results by screenshot file size (largest first)

        Args:
            results: List of results to sort

        Returns:
            Sorted list of results
        """

        def get_file_size(result: ScanResult) -> int:
            """Get file size in bytes, return 0 if no screenshot"""
            if result.screenshot_path and result.screenshot_path.exists():
                return result.screenshot_path.stat().st_size
            return 0

        return sorted(results, key=get_file_size, reverse=True)

    def _normalize_title(self, title: str, max_length: int = 60) -> str:
        """Normalize and truncate a page title."""
        title = title.strip()
        title = " ".join(title.split())
        if len(title) > max_length:
            title = title[:max_length] + "..."
        return title

    def _group_by_title_and_status(
        self, results: List[ScanResult]
    ) -> Dict[str, List[ScanResult]]:
        """
        Group by page title and status code

        Args:
            results: List of successful results

        Returns:
            Dictionary of grouped results
        """
        groups = defaultdict(list)

        for result in results:
            # Generate group key
            if result.page_title and result.page_title.strip():
                title = self._normalize_title(result.page_title)
                group_key = f"{title}"
            else:
                # Group by status code if no title
                status = result.status_code or "Unknown"
                group_key = f"HTTP {status}"

            groups[group_key].append(result)

        return groups

    def _is_screenshot_blank(self, screenshot_path: Path) -> bool:
        """
        Check if screenshot is blank or mostly empty

        Args:
            screenshot_path: Path to screenshot file

        Returns:
            True if screenshot appears blank
        """
        if not screenshot_path.exists():
            return True

        # Check file size (blank screenshots are typically < 3KB)
        file_size = screenshot_path.stat().st_size
        if file_size < 3000:
            return True

        return False

    def _group_by_visual_similarity(
        self, results: List[ScanResult]
    ) -> Dict[str, List[ScanResult]]:
        """
        Group by visual similarity using perceptual hashing

        Args:
            results: List of successful results

        Returns:
            Dictionary of grouped results
        """
        if not IMAGEHASH_AVAILABLE:
            return self._group_by_title_and_status(results)

        groups: Dict[str, List[ScanResult]] = defaultdict(list)
        hash_to_group: Dict[Any, str] = {}  # Map hash to group key
        similarity_threshold = 5  # Hamming distance threshold (more strict)

        # Separate results with valid screenshots from those without
        results_without_screenshots = []

        for result in results:
            if not result.screenshot_path or not result.screenshot_path.exists():
                results_without_screenshots.append(result)
                continue

            if self._is_screenshot_blank(result.screenshot_path):
                results_without_screenshots.append(result)
                continue

            try:
                # Calculate perceptual hash
                img = Image.open(result.screenshot_path)
                img_hash = imagehash.phash(img)  # Use phash for better accuracy

                # Find similar group
                matched_group = None
                for existing_hash, group_key in hash_to_group.items():
                    if img_hash - existing_hash <= similarity_threshold:
                        matched_group = group_key
                        break

                if matched_group:
                    # Add to existing group
                    groups[matched_group].append(result)
                else:
                    # Create new group
                    # Use title as group name, fallback to first URL
                    if result.page_title and result.page_title.strip():
                        title = self._normalize_title(result.page_title)
                        group_key = f"{title}"
                    else:
                        # Use first URL of this visual group
                        host = result.target.host
                        if len(host) > 40:
                            host = host[:40] + "..."
                        group_key = f"{host}"

                    # Ensure unique group key
                    original_key = group_key
                    counter = 1
                    while group_key in groups:
                        group_key = f"{original_key} ({counter})"
                        counter += 1

                    groups[group_key].append(result)
                    hash_to_group[img_hash] = group_key

            except Exception as e:
                self.logger.warning(
                    f"Failed to hash {result.screenshot_path.name}: {e}"
                )
                results_without_screenshots.append(result)

        # Group results without screenshots by title
        if results_without_screenshots:
            title_groups = self._group_by_title_and_status(results_without_screenshots)
            groups.update(title_groups)

        return groups

    def _group_failures(self, results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """
        Group failed results by error type

        Args:
            results: List of failed results

        Returns:
            Dictionary of grouped results
        """
        groups = defaultdict(list)

        for result in results:
            if result.status_code:
                # Group by HTTP status code
                status = result.status_code
                if 400 <= status < 500:
                    group_key = "Client Errors (4xx)"
                elif 500 <= status < 600:
                    group_key = "Server Errors (5xx)"
                else:
                    group_key = f"HTTP {status}"
            elif result.error:
                # Group by error type
                error = result.error.lower()
                if "timeout" in error:
                    group_key = "Timeouts"
                elif "connection" in error or "refused" in error:
                    group_key = "Connection Refused"
                elif "ssl" in error or "certificate" in error:
                    group_key = "SSL/Certificate Errors"
                else:
                    group_key = "Other Errors"
            else:
                group_key = "Unknown Failures"

            groups[group_key].append(result)

        return groups
