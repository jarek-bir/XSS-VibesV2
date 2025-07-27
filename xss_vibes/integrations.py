"""Integration with external tools like Arjun and ParamSpider."""

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin
import re

from .config import ScannerConfig
from .models import ScanTarget


logger = logging.getLogger("xss_vibes.integrations")


class ArjunIntegration:
    """Integration with Arjun parameter discovery tool."""

    def __init__(self, config: ScannerConfig):
        """Initialize Arjun integration."""
        self.config = config

    def is_available(self) -> bool:
        """Check if Arjun is installed and available."""
        try:
            result = subprocess.run(
                ["arjun", "--help"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    async def discover_parameters(
        self, url: str, wordlist: Optional[str] = None
    ) -> List[str]:
        """
        Discover hidden parameters using Arjun.

        Args:
            url: Target URL to scan
            wordlist: Custom wordlist path (optional)

        Returns:
            List of discovered parameter names
        """
        if not self.is_available():
            logger.warning("Arjun not found. Install with: pip3 install arjun")
            return []

        try:
            # Create a temporary file for Arjun output
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as temp_file:
                output_file = temp_file.name

            # Prepare Arjun command
            cmd = [
                "arjun",
                "-u",
                url,
                "-oJ",
                output_file,  # Use temporary file
                "--stable",  # More stable detection
                "-t",
                str(min(self.config.max_threads, 5)),  # Limit threads
                "-d",
                str(self.config.default_timeout),  # Timeout
            ]

            if wordlist and Path(wordlist).exists():
                cmd.extend(["-w", wordlist])

            # Add proxy support if configured
            proxy_dict = self.config.get_proxy_dict()
            if proxy_dict and proxy_dict.get("http"):
                cmd.extend(["--proxy", proxy_dict["http"]])

            logger.info(f"Running Arjun parameter discovery on {url}")

            # Run Arjun in a separate process
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=180  # 3 minutes timeout
            )

            if process.returncode != 0:
                logger.error(f"Arjun failed: {stderr.decode()}")
                return []

            # Read Arjun JSON output from file
            parameters = []

            if Path(output_file).exists():
                with open(output_file, "r") as f:
                    output = f.read()
                parameters = self._parse_arjun_output(output, url)

                # Clean up temporary file
                Path(output_file).unlink(missing_ok=True)

            if parameters:
                logger.info(
                    f"Arjun discovered {len(parameters)} parameters: {', '.join(parameters)}"
                )
            else:
                logger.info("Arjun found no additional parameters")

            return parameters

        except asyncio.TimeoutError:
            logger.error("Arjun discovery timed out")
            return []
        except Exception as e:
            logger.error(f"Arjun discovery failed: {e}")
            return []

    def _parse_arjun_output(self, output: str, url: str) -> List[str]:
        """Parse Arjun JSON output to extract parameters."""
        try:
            # Look for JSON output in the text
            json_match = re.search(r"\{.*\}", output, re.DOTALL)
            if not json_match:
                return []

            data = json.loads(json_match.group())

            # Extract parameters from Arjun results
            parameters = []
            if isinstance(data, dict):
                # Look for the URL entry
                for key, value in data.items():
                    if url in key and isinstance(value, list):
                        parameters.extend(value)
                    elif isinstance(value, dict) and "parameters" in value:
                        parameters.extend(value["parameters"])

            return list(set(parameters))  # Remove duplicates

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse Arjun output: {e}")
            return []


class ParamSpiderIntegration:
    """Integration with ParamSpider for parameter collection from web archives."""

    def __init__(self, config: ScannerConfig):
        """Initialize ParamSpider integration."""
        self.config = config

    def is_available(self) -> bool:
        """Check if ParamSpider is installed and available."""
        try:
            result = subprocess.run(
                ["python3", "-c", "import paramspider"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            # Try alternative check
            try:
                result = subprocess.run(
                    ["paramspider", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result.returncode == 0
            except:
                return False

    async def collect_parameters(
        self, domain: str, output_dir: Optional[str] = None
    ) -> List[str]:
        """
        Collect parameters from web archives using ParamSpider.

        Args:
            domain: Target domain to collect parameters for
            output_dir: Output directory for results

        Returns:
            List of URLs with parameters found in archives
        """
        if not self.is_available():
            logger.warning(
                "ParamSpider not found. Install with: pip3 install paramspider"
            )
            return []

        try:
            # Create temporary directory if none provided
            if not output_dir:
                temp_dir = tempfile.mkdtemp()
                output_dir = temp_dir

            # Prepare ParamSpider command
            cmd = [
                "python3",
                "-m",
                "paramspider",
                "-d",
                domain,
                "-o",
                output_dir,
                "--level",
                "high",
            ]

            logger.info(f"Running ParamSpider on domain {domain}")

            # Run ParamSpider
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=300  # 5 minutes timeout
            )

            if process.returncode != 0:
                logger.error(f"ParamSpider failed: {stderr.decode()}")
                return []

            # Parse ParamSpider output files
            urls = self._parse_paramspider_results(output_dir, domain)

            logger.info(f"ParamSpider found {len(urls)} URLs with parameters")
            return urls

        except asyncio.TimeoutError:
            logger.error("ParamSpider collection timed out")
            return []
        except Exception as e:
            logger.error(f"ParamSpider collection failed: {e}")
            return []

    def _parse_paramspider_results(self, output_dir: str, domain: str) -> List[str]:
        """Parse ParamSpider output files."""
        urls = []

        try:
            output_path = Path(output_dir)

            # Look for ParamSpider output files
            for file_path in output_path.rglob("*.txt"):
                if domain in file_path.name:
                    with open(file_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and line.startswith("http") and "?" in line:
                                urls.append(line)

            return list(set(urls))  # Remove duplicates

        except Exception as e:
            logger.error(f"Failed to parse ParamSpider results: {e}")
            return []


class ParameterDiscovery:
    """Main class for parameter discovery using multiple tools."""

    def __init__(self, config: ScannerConfig):
        """Initialize parameter discovery."""
        self.config = config
        self.arjun = ArjunIntegration(config)
        self.paramspider = ParamSpiderIntegration(config)

    async def discover_all_parameters(
        self, url: str, use_archives: bool = True
    ) -> Dict[str, List[str]]:
        """
        Discover parameters using all available tools.

        Args:
            url: Target URL
            use_archives: Whether to use web archives (ParamSpider)

        Returns:
            Dictionary with discovered parameters and URLs
        """
        results = {"arjun_params": [], "archive_urls": [], "enhanced_targets": []}

        # Parse URL to get domain
        parsed = urlparse(url)
        domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Run Arjun parameter discovery
        if self.arjun.is_available():
            logger.info("🔍 Discovering hidden parameters with Arjun...")
            arjun_params = await self.arjun.discover_parameters(url)
            results["arjun_params"] = arjun_params

            # Create enhanced URLs with discovered parameters
            for param in arjun_params:
                enhanced_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                results["enhanced_targets"].append(enhanced_url)

        # Run ParamSpider archive collection
        if use_archives and self.paramspider.is_available():
            logger.info("🕷️ Collecting parameters from web archives with ParamSpider...")
            archive_urls = await self.paramspider.collect_parameters(domain)
            results["archive_urls"] = archive_urls

            # Filter archive URLs to same domain
            for archive_url in archive_urls:
                if domain in archive_url:
                    results["enhanced_targets"].append(archive_url)

        # Remove duplicates and limit results
        results["enhanced_targets"] = list(set(results["enhanced_targets"]))[
            :50
        ]  # Limit to 50 URLs

        logger.info(f"📈 Parameter discovery complete:")
        logger.info(f"   Arjun parameters: {len(results['arjun_params'])}")
        logger.info(f"   Archive URLs: {len(results['archive_urls'])}")
        logger.info(f"   Enhanced targets: {len(results['enhanced_targets'])}")

        return results

    def enhance_scan_targets(
        self, targets: List[ScanTarget], discovery_results: Dict[str, List[str]]
    ) -> List[ScanTarget]:
        """
        Enhance existing scan targets with discovered parameters.

        Args:
            targets: Original scan targets
            discovery_results: Results from parameter discovery

        Returns:
            Enhanced list of scan targets
        """
        enhanced_targets = targets.copy()

        # Add targets from enhanced URLs
        for url in discovery_results.get("enhanced_targets", []):
            try:
                target = ScanTarget(url=url)
                if target.parameters:  # Only add if it has parameters
                    enhanced_targets.append(target)
            except Exception as e:
                logger.warning(f"Failed to create target from {url}: {e}")

        return enhanced_targets


def install_tools() -> Dict[str, bool]:
    """
    Check and optionally install required tools.

    Returns:
        Dictionary showing installation status of each tool
    """
    status = {}

    # Check Arjun
    try:
        subprocess.run(["arjun", "--help"], capture_output=True, timeout=10)
        status["arjun"] = True
    except:
        status["arjun"] = False
        logger.info("Arjun not found. Install with: pip3 install arjun")

    # Check ParamSpider
    try:
        subprocess.run(
            ["python3", "-c", "import paramspider"], capture_output=True, timeout=10
        )
        status["paramspider"] = True
    except:
        status["paramspider"] = False
        logger.info("ParamSpider not found. Install with: pip3 install paramspider")

    return status
