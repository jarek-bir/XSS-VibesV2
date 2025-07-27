"""Modern XSS scanner engine."""

import asyncio
import logging
import time
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ScannerConfig
from .models import (
    ScanTarget,
    ScanResult,
    VulnerabilityResult,
    VulnerabilityLevel,
    ScanStatus,
    Payload,
)
from .payload_manager import PayloadManager
from .waf_detector import WAFDetector
from .http_client import AsyncHTTPClient, SyncHTTPClient


logger = logging.getLogger("xss_vibes.scanner")


class XSSScanner:
    """Modern XSS scanner with async support."""

    def __init__(
        self,
        config: Optional[ScannerConfig] = None,
        payload_manager: Optional[PayloadManager] = None,
        waf_detector: Optional[WAFDetector] = None,
    ):
        """
        Initialize XSS scanner.

        Args:
            config: Scanner configuration
            payload_manager: Payload manager instance
            waf_detector: WAF detector instance
        """
        self.config = config or ScannerConfig()
        self.payload_manager = payload_manager or PayloadManager(
            self.config.payloads_file
        )
        self.waf_detector = waf_detector or WAFDetector(self.config.waf_list_file)

    async def scan_url_async(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
        detect_waf: bool = True,
        custom_waf: Optional[str] = None,
        waf_mode: bool = False,
        target_waf: Optional[str] = None,
        use_enhanced_payloads: bool = False,
        payload_category: Optional[str] = None,
    ) -> ScanResult:
        """
        Perform async XSS scan on a single URL.

        Args:
            url: Target URL to scan
            custom_headers: Custom HTTP headers
            detect_waf: Whether to detect WAF
            custom_waf: Custom WAF type to use

        Returns:
            ScanResult object
        """
        start_time = time.time()
        target = ScanTarget(url=url)
        result = ScanResult(target=target)

        try:
            target.status = ScanStatus.SCANNING

            # Check if URL has parameters
            if not target.parameters:
                logger.warning(f"No GET parameters found in {url}")
                result.errors.append("No GET parameters found")
                target.status = ScanStatus.SAFE
                return result

            logger.info(f"Scanning {url} with {len(target.parameters)} parameters")

            # WAF detection
            detected_waf = None
            if custom_waf:
                detected_waf = custom_waf
                logger.info(f"Using custom WAF: {custom_waf}")
            elif detect_waf:
                detected_waf = self.waf_detector.detect_waf(url)
                if detected_waf:
                    logger.info(f"Detected WAF: {detected_waf}")
                    result.waf_detected = detected_waf

            # Test dangerous characters first
            async with AsyncHTTPClient(self.config) as client:
                reflected_chars = await self._test_character_reflection(
                    client, target, custom_headers
                )

                if not reflected_chars:
                    logger.info("No dangerous characters reflected")
                    target.status = ScanStatus.SAFE
                    return result

                logger.info(f"Reflected characters: {reflected_chars}")

                # Get suitable payloads based on mode
                if waf_mode and detected_waf:
                    # Use WAF-specific payloads
                    payloads = self.payload_manager.get_all_payloads_combined(
                        waf_type=detected_waf
                    )
                    logger.info(
                        f"Using {len(payloads)} WAF-specific payloads for {detected_waf}"
                    )
                else:
                    # Use standard filtered payloads
                    payloads = self.payload_manager.get_filtered_payloads(
                        reflected_chars, detected_waf
                    )

                if not payloads:
                    logger.warning("No suitable payloads found")
                    target.status = ScanStatus.SAFE
                    return result

                logger.info(f"Testing {len(payloads)} payloads")

                # Test payloads
                vulnerabilities = await self._test_payloads(
                    client, target, payloads, custom_headers
                )

                result.vulnerabilities.extend(vulnerabilities)

                if vulnerabilities:
                    target.status = ScanStatus.VULNERABLE
                    logger.warning(f"Found {len(vulnerabilities)} vulnerabilities!")
                else:
                    target.status = ScanStatus.SAFE
                    logger.info("No vulnerabilities found")

        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
            result.errors.append(str(e))
            target.status = ScanStatus.ERROR

        finally:
            result.scan_duration = time.time() - start_time

        return result

    def scan_url_sync(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
        detect_waf: bool = True,
        custom_waf: Optional[str] = None,
        waf_mode: bool = False,
        target_waf: Optional[str] = None,
        use_enhanced_payloads: bool = False,
        payload_category: Optional[str] = None,
    ) -> ScanResult:
        """
        Perform synchronous XSS scan on a single URL.

        Args:
            url: Target URL to scan
            custom_headers: Custom HTTP headers
            detect_waf: Whether to detect WAF
            custom_waf: Custom WAF type to use

        Returns:
            ScanResult object
        """
        start_time = time.time()
        target = ScanTarget(url=url)
        result = ScanResult(target=target)

        try:
            target.status = ScanStatus.SCANNING

            if not target.parameters:
                logger.warning(f"No GET parameters found in {url}")
                result.errors.append("No GET parameters found")
                target.status = ScanStatus.SAFE
                return result

            logger.info(f"Scanning {url} with {len(target.parameters)} parameters")

            # WAF detection
            detected_waf = None
            if custom_waf:
                detected_waf = custom_waf
            elif detect_waf:
                detected_waf = self.waf_detector.detect_waf(url)
                if detected_waf:
                    result.waf_detected = detected_waf

            # Use sync client
            client = SyncHTTPClient(self.config)

            # Test character reflection
            reflected_chars = self._test_character_reflection_sync(
                client, target, custom_headers
            )

            if not reflected_chars:
                target.status = ScanStatus.SAFE
                return result

            # Get and test payloads
            payloads = self.payload_manager.get_filtered_payloads(
                reflected_chars, detected_waf
            )

            if payloads:
                vulnerabilities = self._test_payloads_sync(
                    client, target, payloads, custom_headers
                )
                result.vulnerabilities.extend(vulnerabilities)

                if vulnerabilities:
                    target.status = ScanStatus.VULNERABLE
                else:
                    target.status = ScanStatus.SAFE
            else:
                target.status = ScanStatus.SAFE

        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
            result.errors.append(str(e))
            target.status = ScanStatus.ERROR

        finally:
            result.scan_duration = time.time() - start_time

        return result

    async def scan_urls_async(
        self, urls: List[str], custom_headers: Optional[Dict[str, str]] = None, **kwargs
    ) -> List[ScanResult]:
        """
        Scan multiple URLs asynchronously.

        Args:
            urls: List of URLs to scan
            custom_headers: Custom HTTP headers
            **kwargs: Additional arguments for scan_url_async

        Returns:
            List of ScanResult objects
        """
        logger.info(f"Starting async scan of {len(urls)} URLs")

        semaphore = asyncio.Semaphore(self.config.max_threads)

        async def scan_with_semaphore(url: str) -> ScanResult:
            async with semaphore:
                return await self.scan_url_async(url, custom_headers, **kwargs)

        tasks = [scan_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error scanning {urls[i]}: {result}")
                error_result = ScanResult(target=ScanTarget(url=urls[i]))
                error_result.errors.append(str(result))
                error_result.target.status = ScanStatus.ERROR
                scan_results.append(error_result)
            else:
                scan_results.append(result)

        return scan_results

    def scan_urls_sync(
        self,
        urls: List[str],
        custom_headers: Optional[Dict[str, str]] = None,
        max_workers: Optional[int] = None,
        **kwargs,
    ) -> List[ScanResult]:
        """
        Scan multiple URLs using thread pool.

        Args:
            urls: List of URLs to scan
            custom_headers: Custom HTTP headers
            max_workers: Maximum number of worker threads
            **kwargs: Additional arguments for scan_url_sync

        Returns:
            List of ScanResult objects
        """
        logger.info(f"Starting sync scan of {len(urls)} URLs")

        max_workers = max_workers or self.config.max_threads
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.scan_url_sync, url, custom_headers, **kwargs): url
                for url in urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {e}")
                    error_result = ScanResult(target=ScanTarget(url=url))
                    error_result.errors.append(str(e))
                    error_result.target.status = ScanStatus.ERROR
                    results.append(error_result)

        return results

    async def _test_character_reflection(
        self,
        client: AsyncHTTPClient,
        target: ScanTarget,
        headers: Optional[Dict[str, str]],
    ) -> Set[str]:
        """Test which dangerous characters are reflected."""
        dangerous_chars = self.payload_manager.get_dangerous_characters()
        reflected_chars = set()

        for param in target.parameters:
            for char in dangerous_chars:
                test_value = char + "randomstring"

                response = await client.test_payload(
                    target.url, param, test_value, headers
                )

                if response.status == 200 and test_value in response.content:
                    reflected_chars.add(char)
                    logger.debug(f"Character '{char}' reflected in parameter {param}")

        return reflected_chars

    def _test_character_reflection_sync(
        self,
        client: SyncHTTPClient,
        target: ScanTarget,
        headers: Optional[Dict[str, str]],
    ) -> Set[str]:
        """Test which dangerous characters are reflected (sync version)."""
        dangerous_chars = self.payload_manager.get_dangerous_characters()
        reflected_chars = set()

        for param in target.parameters:
            for char in dangerous_chars:
                test_value = char + "randomstring"

                # Parse URL and create test parameters
                parsed = urlparse(target.url)
                existing_params = parse_qs(parsed.query) if parsed.query else {}
                params = {
                    k: v[0] if isinstance(v, list) and v else str(v)
                    for k, v in existing_params.items()
                }
                params[param] = test_value

                # Build clean URL
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                response = client.get(base_url, params=params, headers=headers)

                if response.status == 200 and test_value in response.content:
                    reflected_chars.add(char)

        return reflected_chars

    async def _test_payloads(
        self,
        client: AsyncHTTPClient,
        target: ScanTarget,
        payloads: List[Payload],
        headers: Optional[Dict[str, str]],
    ) -> List[VulnerabilityResult]:
        """Test payloads against target parameters."""
        vulnerabilities = []

        for param in target.parameters:
            for payload in payloads:
                response = await client.test_payload(
                    target.url, param, payload.content, headers
                )

                if response.status == 200 and payload.content in response.content:
                    vuln = VulnerabilityResult(
                        url=target.url,
                        parameter=param,
                        payload=payload.content,
                        level=payload.level,
                        response_snippet=response.content[:500],
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Vulnerability found: {param} -> {payload.content}")

                    # Stop after first vulnerability per parameter
                    break

        return vulnerabilities

    def _test_payloads_sync(
        self,
        client: SyncHTTPClient,
        target: ScanTarget,
        payloads: List[Payload],
        headers: Optional[Dict[str, str]],
    ) -> List[VulnerabilityResult]:
        """Test payloads against target parameters (sync version)."""
        vulnerabilities = []

        for param in target.parameters:
            for payload in payloads:
                # Parse URL and create test parameters
                parsed = urlparse(target.url)
                existing_params = parse_qs(parsed.query) if parsed.query else {}
                params = {
                    k: v[0] if isinstance(v, list) and v else str(v)
                    for k, v in existing_params.items()
                }
                params[param] = payload.content

                # Build clean URL
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                response = client.get(base_url, params=params, headers=headers)

                if response.status == 200 and payload.content in response.content:
                    vuln = VulnerabilityResult(
                        url=target.url,
                        parameter=param,
                        payload=payload.content,
                        level=payload.level,
                        response_snippet=response.content[:500],
                    )
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities
