"""
Screenshot engine using Playwright
"""

import logging
from pathlib import Path
from typing import Optional

from playwright.async_api import Browser, async_playwright

from webssy.models import Config, ScanResult, Target
from webssy.utils.output import get_screenshot_filename


class ScreenshotEngine:
    """Screenshot capture using Playwright"""

    def __init__(self, config: Config, screenshots_dir: Path):
        """
        Initialize screenshot engine

        Args:
            config: Global configuration
            screenshots_dir: Directory to save screenshots
        """
        self.config = config
        self.screenshots_dir = screenshots_dir
        self.logger = logging.getLogger("webssy")
        self._browser: Optional[Browser] = None
        self._playwright = None

    async def __aenter__(self):
        """Enter context manager - launch browser"""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True, args=["--disable-dev-shm-usage", "--no-sandbox"]
        )
        self.logger.info("Browser launched")
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        """Exit context manager - close browser"""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self.logger.info("Browser closed")

    async def capture(
        self,
        target: Target,
        status_code: Optional[int] = None,
        final_url: Optional[str] = None,
    ) -> ScanResult:
        """
        Capture screenshot for a target

        Args:
            target: Target to capture
            status_code: HTTP status code from probe
            final_url: Final URL after redirects

        Returns:
            ScanResult with screenshot path or error
        """
        import time

        start_time = time.time()

        url = final_url or target.get_url()
        filename = get_screenshot_filename(
            target.host, target.port, target.protocol.value
        )
        screenshot_path = self.screenshots_dir / filename

        context = None
        page = None
        try:
            # Create isolated context for this capture
            if not self._browser:
                raise RuntimeError("Browser not initialized")

            context = await self._browser.new_context(
                viewport={
                    "width": self.config.screenshot_width,
                    "height": self.config.screenshot_height,
                },
                ignore_https_errors=self.config.ignore_https_errors,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )

            # Set default timeout for all operations in this context (in milliseconds)
            context.set_default_timeout(self.config.timeout * 1000)

            page = await context.new_page()

            # Navigate (uses context's default timeout)
            await page.goto(url, wait_until="load")

            # Some pages (e.g. ESXi, SPAs) trigger successive JS redirects after
            # load, destroying the execution context each time. Loop until the
            # context is stable or we hit the retry limit.
            page_title = ""
            for _ in range(5):
                try:
                    page_title = await page.title()
                    break
                except Exception:
                    try:
                        await page.wait_for_load_state("load")
                    except Exception:
                        break

            await page.screenshot(path=str(screenshot_path), full_page=False)

            duration_ms = int((time.time() - start_time) * 1000)

            self.logger.debug(f"Screenshot captured: {url} -> {screenshot_path.name}")

            return ScanResult(
                target=target,
                success=True,
                final_url=url,
                status_code=status_code,
                screenshot_path=screenshot_path,
                page_title=page_title,
                duration_ms=duration_ms,
                protocol_used=target.protocol,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            self.logger.debug(f"Screenshot error: {url} - {e}")
            return ScanResult(
                target=target,
                success=False,
                final_url=url,
                status_code=status_code,
                error=str(e),
                duration_ms=duration_ms,
                protocol_used=target.protocol,
            )

        finally:
            # Close page first, then context to properly cleanup
            if page:
                try:
                    await page.close()
                except Exception:
                    pass  # Ignore errors during cleanup

            if context:
                try:
                    await context.close()
                except Exception:
                    pass  # Ignore errors during cleanup
