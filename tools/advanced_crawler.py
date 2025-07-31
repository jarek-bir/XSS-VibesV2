#!/usr/bin/env python3
"""
XSS Vibes V2 - Advanced Endpoint Crawler
Based on Osmedeus architecture with Fofa/Shodan integration
"""

import asyncio
import aiohttp
import json
import requests
import subprocess
import time
import logging
from pathlib import Path
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import yaml
import base64
import re
from concurrent.futures import ThreadPoolExecutor


class AdvancedCrawler:
    def __init__(self, config_file="config/crawler_config.yaml"):
        self.config = self.load_config(config_file)
        self.session = None
        self.endpoints = set()
        self.vulnerabilities = []
        self.setup_logging()

    def load_config(self, config_file):
        """Load crawler configuration"""
        default_config = {
            "fofa": {"email": "", "key": "", "enabled": False},
            "shodan": {"api_key": "", "enabled": False},
            "crawling": {
                "max_depth": 5,
                "delay": 0.5,
                "timeout": 30,
                "threads": 50,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
            "nuclei": {
                "templates_path": "~/nuclei-templates/",
                "severity": "critical,high,medium,low,info",
                "threads": 100,
                "timeout": "2h",
            },
            "jaeles": {
                "signatures": "~/.jaeles/base-signatures/",
                "threads": 50,
                "timeout": "1h",
            },
            "output": {"directory": "output", "format": ["json", "html", "txt"]},
        }

        try:
            with open(config_file, "r") as f:
                config = yaml.safe_load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            print(f"⚠️  Config file not found, using defaults")
            return default_config

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("crawler.log"), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

    async def init_session(self):
        """Initialize aiohttp session"""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
        timeout = aiohttp.ClientTimeout(total=self.config["crawling"]["timeout"])
        headers = {"User-Agent": self.config["crawling"]["user_agent"]}

        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()

    def fofa_search(self, query: str, size: int = 1000) -> List[Dict]:
        """Search using Fofa API"""
        if not self.config["fofa"]["enabled"]:
            self.logger.warning("Fofa integration disabled")
            return []

        fofa_email = self.config["fofa"]["email"]
        fofa_key = self.config["fofa"]["key"]

        if not fofa_email or not fofa_key:
            self.logger.error("Fofa credentials not configured")
            return []

        self.logger.info(f"🔍 Searching Fofa: {query}")

        # Encode query to base64
        query_encoded = base64.b64encode(query.encode()).decode()

        url = f"https://fofa.info/api/v1/search/all"
        params = {
            "email": fofa_email,
            "key": fofa_key,
            "qbase64": query_encoded,
            "size": size,
            "fields": "host,ip,port,protocol,domain,title,server,banner",
        }

        try:
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("error", False):
                    self.logger.error(
                        f"Fofa API error: {data.get('errmsg', 'Unknown error')}"
                    )
                    return []

                results = []
                for result in data.get("results", []):
                    if len(result) >= 4:  # host, ip, port, protocol
                        host = result[0]
                        ip = result[1]
                        port = result[2]
                        protocol = result[3]

                        results.append(
                            {
                                "host": host,
                                "ip": ip,
                                "port": port,
                                "protocol": protocol,
                                "url": (
                                    f"{protocol}://{host}:{port}"
                                    if port not in ["80", "443"]
                                    else f"{protocol}://{host}"
                                ),
                                "domain": result[4] if len(result) > 4 else host,
                                "title": result[5] if len(result) > 5 else "",
                                "server": result[6] if len(result) > 6 else "",
                                "banner": result[7] if len(result) > 7 else "",
                            }
                        )

                self.logger.info(f"✅ Fofa found {len(results)} results")
                return results

        except Exception as e:
            self.logger.error(f"Fofa search failed: {e}")
            return []

    def shodan_search(self, query: str, limit: int = 1000) -> List[Dict]:
        """Search using Shodan API"""
        if not self.config["shodan"]["enabled"]:
            self.logger.warning("Shodan integration disabled")
            return []

        api_key = self.config["shodan"]["api_key"]
        if not api_key:
            self.logger.error("Shodan API key not configured")
            return []

        self.logger.info(f"🔍 Searching Shodan: {query}")

        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": api_key, "query": query, "limit": limit}

        try:
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                results = []

                for match in data.get("matches", []):
                    ip = match.get("ip_str", "")
                    port = match.get("port", 80)
                    domains = match.get("domains", [])
                    hostnames = match.get("hostnames", [])

                    # Use first domain/hostname or IP
                    host = (
                        domains[0] if domains else (hostnames[0] if hostnames else ip)
                    )

                    # Determine protocol
                    if port == 443 or "ssl" in match.get("transport", "").lower():
                        protocol = "https"
                    else:
                        protocol = "http"

                    results.append(
                        {
                            "host": host,
                            "ip": ip,
                            "port": port,
                            "protocol": protocol,
                            "url": (
                                f"{protocol}://{host}:{port}"
                                if port not in [80, 443]
                                else f"{protocol}://{host}"
                            ),
                            "domains": domains,
                            "hostnames": hostnames,
                            "banner": match.get("data", ""),
                            "product": match.get("product", ""),
                            "version": match.get("version", ""),
                            "country": match.get("location", {}).get(
                                "country_name", ""
                            ),
                            "org": match.get("org", ""),
                        }
                    )

                self.logger.info(f"✅ Shodan found {len(results)} results")
                return results

        except Exception as e:
            self.logger.error(f"Shodan search failed: {e}")
            return []

    async def crawl_endpoints(self, url: str, depth: int = 0) -> Set[str]:
        """Crawl endpoints from a given URL"""
        if depth > self.config["crawling"]["max_depth"]:
            return set()

        endpoints = set()

        try:
            self.logger.info(f"🕷️  Crawling: {url} (depth: {depth})")

            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()

                    # Extract endpoints using various methods
                    endpoints.update(self.extract_urls_from_html(content, url))
                    endpoints.update(self.extract_api_endpoints(content, url))
                    endpoints.update(self.extract_js_endpoints(content, url))

                    # Crawl JavaScript files
                    js_urls = self.extract_js_files(content, url)
                    for js_url in js_urls:
                        js_endpoints = await self.crawl_js_file(js_url)
                        endpoints.update(js_endpoints)

                    # Recursive crawling (limited depth)
                    if depth < self.config["crawling"]["max_depth"]:
                        page_links = self.extract_page_links(content, url)
                        for link in list(page_links)[:10]:  # Limit to 10 links per page
                            sub_endpoints = await self.crawl_endpoints(link, depth + 1)
                            endpoints.update(sub_endpoints)

        except Exception as e:
            self.logger.error(f"Failed to crawl {url}: {e}")

        await asyncio.sleep(self.config["crawling"]["delay"])
        return endpoints

    def extract_urls_from_html(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML content"""
        urls = set()

        # Common URL patterns
        patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
            r'action=["\'](.*?)["\']',
            r'data-url=["\'](.*?)["\']',
            r'url\(["\'](.*?)["\']\)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if (
                    match
                    and not match.startswith("#")
                    and not match.startswith("javascript:")
                ):
                    full_url = urljoin(base_url, match)
                    urls.add(full_url)

        return urls

    def extract_api_endpoints(self, content: str, base_url: str) -> Set[str]:
        """Extract API endpoints from content"""
        endpoints = set()

        # API endpoint patterns
        api_patterns = [
            r"/api/[a-zA-Z0-9/_-]+",
            r"/v\d+/[a-zA-Z0-9/_-]+",
            r"/rest/[a-zA-Z0-9/_-]+",
            r"/graphql/?",
            r"\.json",
            r"\.xml",
            r"/ajax/[a-zA-Z0-9/_-]+",
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                endpoints.add(full_url)

        return endpoints

    def extract_js_endpoints(self, content: str, base_url: str) -> Set[str]:
        """Extract endpoints from JavaScript code"""
        endpoints = set()

        # JavaScript endpoint patterns
        js_patterns = [
            r'["\']([/a-zA-Z0-9._-]+\.php)["\']',
            r'["\']([/a-zA-Z0-9._-]+\.asp[x]?)["\']',
            r'["\']([/a-zA-Z0-9._-]+\.jsp)["\']',
            r'["\']([/a-zA-Z0-9._-]+\.do)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post]+\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\(["\'][^"\']*["\'],\s*["\']([^"\']+)["\']',
        ]

        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = (
                        match[0] if match[0] else (match[1] if len(match) > 1 else "")
                    )
                if match and not match.startswith("http"):
                    full_url = urljoin(base_url, match)
                    endpoints.add(full_url)

        return endpoints

    def extract_js_files(self, content: str, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs"""
        js_files = set()

        patterns = [
            r'<script[^>]*src=["\'](.*?\.js.*?)["\']',
            r'import[^"\']+"([^"\']+\.js[^"\']*)"',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                js_files.add(full_url)

        return js_files

    def extract_page_links(self, content: str, base_url: str) -> Set[str]:
        """Extract page links for recursive crawling"""
        links = set()
        domain = urlparse(base_url).netloc

        pattern = r'href=["\'](.*?)["\']'
        matches = re.findall(pattern, content, re.IGNORECASE)

        for match in matches:
            if (
                match
                and not match.startswith("#")
                and not match.startswith("javascript:")
            ):
                full_url = urljoin(base_url, match)
                # Only crawl same domain
                if urlparse(full_url).netloc == domain:
                    links.add(full_url)

        return links

    async def crawl_js_file(self, js_url: str) -> Set[str]:
        """Crawl JavaScript file for endpoints"""
        endpoints = set()

        try:
            async with self.session.get(js_url) as response:
                if response.status == 200:
                    js_content = await response.text()
                    endpoints.update(self.extract_js_endpoints(js_content, js_url))

        except Exception as e:
            self.logger.error(f"Failed to crawl JS file {js_url}: {e}")

        return endpoints

    def run_nuclei_scan(self, targets_file: str) -> List[Dict]:
        """Run Nuclei vulnerability scan"""
        self.logger.info("🔥 Running Nuclei vulnerability scan")

        nuclei_cmd = [
            "nuclei",
            "-l",
            targets_file,
            "-t",
            self.config["nuclei"]["templates_path"],
            "-c",
            str(self.config["nuclei"]["threads"]),
            "-severity",
            self.config["nuclei"]["severity"],
            "-timeout",
            self.config["nuclei"]["timeout"],
            "-json",
            "-silent",
        ]

        try:
            result = subprocess.run(
                nuclei_cmd, capture_output=True, text=True, timeout=7200
            )
            vulnerabilities = []

            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue

            self.logger.info(f"✅ Nuclei found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except subprocess.TimeoutExpired:
            self.logger.error("Nuclei scan timed out")
            return []
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return []

    def run_jaeles_scan(self, targets_file: str) -> List[Dict]:
        """Run Jaeles vulnerability scan"""
        self.logger.info("⚔️  Running Jaeles vulnerability scan")

        jaeles_cmd = [
            "jaeles",
            "scan",
            "-U",
            f"@{targets_file}",
            "-s",
            self.config["jaeles"]["signatures"],
            "-c",
            str(self.config["jaeles"]["threads"]),
            "--timeout",
            self.config["jaeles"]["timeout"],
            "-o",
            f"{self.config['output']['directory']}/jaeles",
            "--fi",
        ]

        try:
            result = subprocess.run(
                jaeles_cmd, capture_output=True, text=True, timeout=3600
            )

            # Parse Jaeles output
            vulnerabilities = []
            output_dir = f"{self.config['output']['directory']}/jaeles"

            if Path(output_dir).exists():
                for vuln_file in Path(output_dir).glob("*.json"):
                    try:
                        with open(vuln_file, "r") as f:
                            vuln_data = json.load(f)
                            vulnerabilities.append(vuln_data)
                    except Exception:
                        continue

            self.logger.info(f"✅ Jaeles found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except subprocess.TimeoutExpired:
            self.logger.error("Jaeles scan timed out")
            return []
        except Exception as e:
            self.logger.error(f"Jaeles scan failed: {e}")
            return []

    def save_results(
        self, targets: List[Dict], endpoints: Set[str], vulnerabilities: List[Dict]
    ):
        """Save crawling and scanning results"""
        output_dir = Path(self.config["output"]["directory"])
        output_dir.mkdir(exist_ok=True)

        # Save targets
        with open(output_dir / "targets.json", "w") as f:
            json.dump(targets, f, indent=2)

        # Save endpoints
        endpoints_list = list(endpoints)
        with open(output_dir / "endpoints.json", "w") as f:
            json.dump(endpoints_list, f, indent=2)

        with open(output_dir / "endpoints.txt", "w") as f:
            for endpoint in sorted(endpoints_list):
                f.write(f"{endpoint}\n")

        # Save vulnerabilities
        with open(output_dir / "vulnerabilities.json", "w") as f:
            json.dump(vulnerabilities, f, indent=2)

        # Generate HTML report
        self.generate_html_report(targets, endpoints, vulnerabilities)

        self.logger.info(f"📊 Results saved to {output_dir}")

    def generate_html_report(
        self, targets: List[Dict], endpoints: Set[str], vulnerabilities: List[Dict]
    ):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vibes V2 - Crawler Report</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2d3748; color: white; padding: 20px; border-radius: 10px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .vulnerability {{ background: #fed7d7; padding: 10px; margin: 5px 0; border-radius: 5px; }}
                .endpoint {{ background: #e6fffa; padding: 5px; margin: 2px 0; border-radius: 3px; }}
                .target {{ background: #f0fff4; padding: 10px; margin: 5px 0; border-radius: 5px; }}
                .stats {{ display: flex; gap: 20px; }}
                .stat {{ background: #4299e1; color: white; padding: 15px; border-radius: 5px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔥 XSS Vibes V2 - Advanced Crawler Report</h1>
                <p>Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <h3>{len(targets)}</h3>
                    <p>Targets Found</p>
                </div>
                <div class="stat">
                    <h3>{len(endpoints)}</h3>
                    <p>Endpoints Discovered</p>
                </div>
                <div class="stat">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Targets</h2>
                {''.join([f'<div class="target"><strong>{t.get("host", "")}</strong> - {t.get("url", "")}</div>' for t in targets[:50]])}
            </div>
            
            <div class="section">
                <h2>🕷️ Endpoints</h2>
                {''.join([f'<div class="endpoint">{endpoint}</div>' for endpoint in list(endpoints)[:100]])}
            </div>
            
            <div class="section">
                <h2>🔥 Vulnerabilities</h2>
                {''.join([f'<div class="vulnerability"><strong>{v.get("template-id", "Unknown")}</strong> - {v.get("matched-at", "")}</div>' for v in vulnerabilities[:50]])}
            </div>
        </body>
        </html>
        """

        output_file = Path(self.config["output"]["directory"]) / "report.html"
        with open(output_file, "w") as f:
            f.write(html_content)

    async def run_comprehensive_scan(
        self,
        fofa_query: str = "",
        shodan_query: str = "",
        direct_targets: List[str] = None,
    ):
        """Run comprehensive crawling and vulnerability scanning"""
        await self.init_session()

        try:
            # Collect targets from various sources
            all_targets = []

            # Fofa search
            if fofa_query:
                fofa_results = self.fofa_search(fofa_query)
                all_targets.extend(fofa_results)

            # Shodan search
            if shodan_query:
                shodan_results = self.shodan_search(shodan_query)
                all_targets.extend(shodan_results)

            # Direct targets
            if direct_targets:
                for target in direct_targets:
                    all_targets.append({"url": target, "host": urlparse(target).netloc})

            if not all_targets:
                self.logger.error("No targets found!")
                return

            self.logger.info(f"🎯 Found {len(all_targets)} total targets")

            # Crawl endpoints from all targets
            all_endpoints = set()
            semaphore = asyncio.Semaphore(self.config["crawling"]["threads"])

            async def crawl_target(target):
                async with semaphore:
                    url = target.get("url", "")
                    if url:
                        endpoints = await self.crawl_endpoints(url)
                        return endpoints
                    return set()

            # Crawl all targets concurrently
            tasks = [
                crawl_target(target) for target in all_targets[:100]
            ]  # Limit to 100 targets
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, set):
                    all_endpoints.update(result)

            self.logger.info(f"🕷️ Discovered {len(all_endpoints)} unique endpoints")

            # Save endpoints to file for vulnerability scanning
            endpoints_file = (
                Path(self.config["output"]["directory"]) / "all_endpoints.txt"
            )
            endpoints_file.parent.mkdir(exist_ok=True)

            with open(endpoints_file, "w") as f:
                for endpoint in all_endpoints:
                    f.write(f"{endpoint}\n")

            # Run vulnerability scans
            vulnerabilities = []

            # Nuclei scan
            nuclei_vulns = self.run_nuclei_scan(str(endpoints_file))
            vulnerabilities.extend(nuclei_vulns)

            # Jaeles scan
            jaeles_vulns = self.run_jaeles_scan(str(endpoints_file))
            vulnerabilities.extend(jaeles_vulns)

            # Save all results
            self.save_results(all_targets, all_endpoints, vulnerabilities)

            self.logger.info("🎉 Comprehensive scan completed!")
            self.logger.info(
                f"📊 Results: {len(all_targets)} targets, {len(all_endpoints)} endpoints, {len(vulnerabilities)} vulnerabilities"
            )

        finally:
            await self.close_session()


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(
        description="XSS Vibes V2 - Advanced Endpoint Crawler"
    )
    parser.add_argument("-f", "--fofa", help="Fofa search query")
    parser.add_argument("-s", "--shodan", help="Shodan search query")
    parser.add_argument("-t", "--targets", nargs="+", help="Direct target URLs")
    parser.add_argument(
        "-c", "--config", default="config/crawler_config.yaml", help="Config file"
    )
    parser.add_argument("-o", "--output", default="output", help="Output directory")

    args = parser.parse_args()

    # Create crawler instance
    crawler = AdvancedCrawler(args.config)
    crawler.config["output"]["directory"] = args.output

    # Run comprehensive scan
    asyncio.run(
        crawler.run_comprehensive_scan(
            fofa_query=args.fofa or "",
            shodan_query=args.shodan or "",
            direct_targets=args.targets,
        )
    )


if __name__ == "__main__":
    main()
