"""
HTTP/HTTPS probing to check if targets are alive
"""

import asyncio
import logging
import ssl
from typing import List, Optional, Tuple

import httpx

from webssy.models import Protocol, Target


class HttpProber:
    def __init__(
        self,
        timeout: int = 2,
        follow_redirects: bool = True,
        certif_discovery: bool = False,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.certif_discovery = certif_discovery
        self.logger = logging.getLogger("webssy")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create shared HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                follow_redirects=self.follow_redirects,
                timeout=self.timeout,
            )
        return self._client

    async def close(self):
        """Close shared HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _extract_cert_hostnames(self, host: str, port: int) -> List[str]:
        """
        Extract hostnames from SSL certificate

        Args:
            host: Target host
            port: Target port

        Returns:
            List of hostnames found in certificate
        """
        hostnames = []

        try:
            # Get certificate using ssl module with timeout
            loop = asyncio.get_event_loop()
            cert_pem = await asyncio.wait_for(
                loop.run_in_executor(None, ssl.get_server_certificate, (host, port)),
                timeout=self.timeout,
            )

            # Parse certificate with cryptography
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )

                # Extract CN from subject
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        cn = attr.value
                        if cn and cn not in hostnames and not cn.startswith("*"):
                            hostnames.append(cn)

                # Extract SANs
                try:
                    san_ext = cert.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    )
                    san_value_obj = san_ext.value
                    # Type assertion for mypy - san_value_obj is SubjectAlternativeName which is iterable
                    for san in san_value_obj:  # type: ignore[attr-defined]
                        if isinstance(san, x509.DNSName):
                            san_value = san.value
                            if san_value not in hostnames and not san_value.startswith(
                                "*"
                            ):
                                hostnames.append(san_value)
                except x509.ExtensionNotFound:
                    pass

            except ImportError:
                self.logger.warning(
                    "cryptography module not available, certificate discovery disabled"
                )

        except Exception as e:
            self.logger.debug(f"Failed to extract certificate from {host}:{port}: {e}")

        return hostnames

    async def probe(
        self, target: Target
    ) -> Tuple[Target, bool, Optional[int], Optional[str], List[str]]:
        """
        Probe a single target

        Args:
            target: Target to probe

        Returns:
            Tuple of (target, success, status_code, final_url, cert_hostnames)
        """
        url = target.get_url()
        cert_hostnames = []

        try:
            client = await self._get_client()
            response = await client.get(url)

            success = response.status_code < 500

            final_url = str(response.url)

            # Extract certificate hostnames AFTER successful HTTPS probe
            if self.certif_discovery and target.protocol == Protocol.HTTPS and success:
                cert_hostnames = await self._extract_cert_hostnames(
                    target.host, target.port
                )
                if cert_hostnames:
                    self.logger.info(f"[CERT] {url} → {', '.join(cert_hostnames)}")

            if final_url != url:
                self.logger.info(f"[{response.status_code}] {url} → {final_url}")
            else:
                self.logger.info(f"[{response.status_code}] {url}")

            return target, success, response.status_code, final_url, cert_hostnames

        except httpx.TimeoutException:
            self.logger.info(f"[TIMEOUT] {url}")
            return target, False, None, None, []
        except httpx.ConnectError:
            self.logger.info(f"[REFUSED] {url}")
            return target, False, None, None, []
        except httpx.HTTPError as e:
            self.logger.debug(f"[HTTP ERROR] {url}: {e}")
            return target, False, None, None, []
        except Exception as e:
            self.logger.debug(f"[ERROR] {url}: {e}")
            return target, False, None, None, []

    async def probe_batch(
        self, targets: list[Target], max_workers: int = 20, progress_callback=None
    ) -> list[Tuple[Target, bool, Optional[int], Optional[str], List[str]]]:
        """
        Probe multiple targets concurrently

        Args:
            targets: List of targets to probe
            max_workers: Maximum concurrent probes
            progress_callback: Optional callback for progress updates

        Returns:
            List of probe results
        """
        from webssy.scanner.worker_pool import WorkerPool

        try:
            pool = WorkerPool(max_workers=max_workers)
            results = await pool.map(
                self.probe, targets, progress_callback=progress_callback
            )
            return results
        finally:
            await self.close()
