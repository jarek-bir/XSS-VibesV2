"""Modern WAF detection module."""

import re
import requests
import logging
from typing import Optional, Dict, List
from pathlib import Path


logger = logging.getLogger("xss_vibes.waf")


class WAFDetector:
    """Modern WAF detection class."""

    def __init__(
        self, waf_list_file: Path = Path(__file__).parent / "data" / "waf_list.txt"
    ):
        """
        Initialize WAF detector.

        Args:
            waf_list_file: Path to file containing known WAF names
        """
        self.waf_list_file = waf_list_file
        self._known_wafs = self._load_waf_list()

    def _load_waf_list(self) -> List[str]:
        """Load known WAF names from file."""
        if not self.waf_list_file.exists():
            logger.warning(f"WAF list file {self.waf_list_file} not found")
            return []

        try:
            with open(self.waf_list_file, "r", encoding="utf-8") as f:
                waf_names = [line.strip().lower() for line in f if line.strip()]

            logger.info(f"Loaded {len(waf_names)} known WAF types")
            return waf_names

        except Exception as e:
            logger.error(f"Error loading WAF list: {e}")
            return []

    def detect_waf(self, url: str, timeout: int = 10) -> Optional[str]:
        """
        Detect WAF for the given URL.

        Args:
            url: URL to check for WAF

        Returns:
            Detected WAF name or None if no WAF detected
        """
        # Simplified detection for binary compatibility
        logger.info(f"Detecting WAF for {url} using header analysis")

        try:
            response = requests.get(url, timeout=10)

            # Check response headers for WAF signatures
            headers = response.headers

            # Cloudflare detection
            if "cf-ray" in headers or "cloudflare" in str(headers).lower():
                logger.info("Detected Cloudflare WAF")
                return "cloudflare"

            # Akamai detection
            if "akamai" in str(headers).lower() or "x-akamai" in str(headers).lower():
                logger.info("Detected Akamai WAF")
                return "akamai"

            # AWS WAF detection
            if "x-amzn" in str(headers).lower() or "aws" in str(headers).lower():
                logger.info("Detected AWS WAF")
                return "aws-waf"

            # Imperva detection
            if "x-iinfo" in headers or "incap" in str(headers).lower():
                logger.info("Detected Imperva WAF")
                return "imperva"

            # Sucuri detection
            if "x-sucuri" in headers or "sucuri" in str(headers).lower():
                logger.info("Detected Sucuri WAF")
                return "sucuri"

            # F5 detection
            if "f5" in str(headers).lower() or "bigip" in str(headers).lower():
                logger.info("Detected F5 WAF")
                return "f5"

            # Barracuda detection
            if "barracuda" in str(headers).lower():
                logger.info("Detected Barracuda WAF")
                return "barracuda"

            # ModSecurity detection
            if (
                "mod_security" in str(headers).lower()
                or "modsec" in str(headers).lower()
            ):
                logger.info("Detected ModSecurity WAF")
                return "modsecurity"

            logger.info("No WAF detected")
            return None

        except Exception as e:
            logger.warning(f"WAF detection failed: {e}")
            return None

    def add_waf_to_list(self, waf_name: str) -> None:
        """
        Add a new WAF name to the known list.

        Args:
            waf_name: Name of the WAF to add
        """
        waf_name = waf_name.lower().strip()
        if waf_name not in self._known_wafs:
            self._known_wafs.append(waf_name)

            # Save to file
            try:
                with open(self.waf_list_file, "a", encoding="utf-8") as f:
                    f.write(f"\n{waf_name}")
                logger.info(f"Added {waf_name} to WAF list")
            except Exception as e:
                logger.error(f"Error saving WAF to list: {e}")

    def get_known_wafs(self) -> List[str]:
        """Get list of known WAF types."""
        return self._known_wafs.copy()

    def is_waf_known(self, waf_name: str) -> bool:
        """Check if a WAF name is in the known list."""
        return waf_name.lower().strip() in self._known_wafs


# Backward compatibility alias
class Waf_Detect:
    """Legacy WAF detection class for backward compatibility."""

    def __init__(self, url: str):
        """Initialize with URL."""
        self.url = url
        self._detector = WAFDetector()

    def waf_detect(self) -> Optional[str]:
        """Legacy method for WAF detection."""
        return self._detector.detect_waf(self.url)

    @staticmethod
    def fetch_names(filename: str) -> List[str]:
        """Legacy method to fetch WAF names from file."""
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return f.read().split()
        except Exception:
            return []
