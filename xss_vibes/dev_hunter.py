#!/usr/bin/env python3
"""
XSS Vibes V2 - Development Interface Hunter
Specialized module for discovering development/staging environments and interfaces
"""

import asyncio
import aiohttp
import re
import json
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import logging
from pathlib import Path


class DevInterfaceHunter:
    def __init__(self):
        self.dev_patterns = self.load_dev_patterns()
        self.setup_logging()
        self.session = None

    def setup_logging(self):
        """Setup logging for dev hunter"""
        self.logger = logging.getLogger("DevHunter")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def load_dev_patterns(self) -> Dict:
        """Load patterns for detecting development interfaces"""
        return {
            "dev_subdomains": [
                "dev",
                "development",
                "devel",
                "develop",
                "staging",
                "stage",
                "test",
                "testing",
                "qa",
                "uat",
                "beta",
                "alpha",
                "demo",
                "sandbox",
                "preview",
                "pre-prod",
                "dev-api",
                "test-api",
                "staging-api",
                "api-dev",
                "api-test",
                "api-staging",
                "admin-dev",
                "dev-admin",
                "test-admin",
                "staging-admin",
            ],
            "dev_paths": [
                # Development directories
                "/dev/",
                "/development/",
                "/devel/",
                "/staging/",
                "/stage/",
                "/test/",
                "/testing/",
                "/qa/",
                "/uat/",
                "/beta/",
                "/alpha/",
                "/demo/",
                "/sandbox/",
                "/preview/",
                # Framework specific
                "/app_dev.php",
                "/web/app_dev.php",
                "/app/app_dev.php",
                "/_dev/",
                "/_development/",
                "/_staging/",
                "/_test/",
                # Admin interfaces
                "/dev-admin/",
                "/test-admin/",
                "/staging-admin/",
                "/admin-dev/",
                "/dev/admin/",
                "/test/admin/",
                "/staging/admin/",
                # API endpoints
                "/dev-api/",
                "/test-api/",
                "/staging-api/",
                "/api/dev/",
                "/api/test/",
                "/api/staging/",
                "/v1/dev/",
                "/v2/dev/",
                "/v1/test/",
                "/v2/test/",
                "/v1/staging/",
                "/v2/staging/",
                # Debug interfaces
                "/debug/",
                "/_debug/",
                "/debugger/",
                "/trace/",
                "/_trace/",
                "/profiler/",
                "/_profiler/",
                "/monitor/",
                "/_monitor/",
                # Documentation
                "/docs/dev/",
                "/docs/staging/",
                "/dev-docs/",
                "/test-docs/",
                "/staging-docs/",
                "/swagger-dev/",
                "/swagger-test/",
                "/api-docs-dev/",
                "/api-docs-test/",
                # Build artifacts
                "/build/",
                "/dist/",
                "/public/",
                "/static/dev/",
                "/assets/dev/",
                "/js/dev/",
                "/css/dev/",
                "/dev.html",
                "/test.html",
                "/staging.html",
            ],
            "dev_files": [
                # Configuration files
                "config.dev.js",
                "config.test.js",
                "config.staging.js",
                "dev.config.js",
                "webpack.dev.js",
                "webpack.test.js",
                "gulpfile.dev.js",
                ".env.dev",
                ".env.test",
                ".env.staging",
                ".env.development",
                "app.dev.js",
                "app.test.js",
                "main.dev.js",
                "main.test.js",
                # Debug files
                "debug.html",
                "test.html",
                "dev.html",
                "staging.html",
                "demo.html",
                "debug.js",
                "test.js",
                "dev.js",
                "staging.js",
                "console.js",
                # Backup/temp files
                "index.dev.html",
                "index.test.html",
                "index.staging.html",
                "app.dev.html",
                "app.test.html",
                "main.dev.html",
                "main.test.html",
            ],
            "content_signatures": [
                # Developer comments
                r"@[Aa]utor?:?\s*([^\\n\\r]+)",
                r"@[Dd]ate:?\s*([^\\n\\r]+)",
                r"@[Ll]ast[Ee]ditors?:?\s*([^\\n\\r]+)",
                r"@[Ll]ast[Ee]dit[Tt]ime:?\s*([^\\n\\r]+)",
                # Development indicators
                r"(?i)<!--.*?development.*?-->",
                r"(?i)<!--.*?staging.*?-->",
                r"(?i)<!--.*?test.*?-->",
                r"(?i)<!--.*?debug.*?-->",
                r"(?i)<!--.*?todo.*?-->",
                r"(?i)<!--.*?fixme.*?-->",
                r"(?i)<!--.*?hack.*?-->",
                # Framework debug modes
                r"(?i)debug\s*=\s*true",
                r"(?i)development\s*=\s*true",
                r"(?i)env\s*=\s*['\"]dev",
                r"(?i)env\s*=\s*['\"]development",
                r"(?i)mode\s*=\s*['\"]dev",
                r"(?i)NODE_ENV\s*=\s*['\"]development",
                # Error messages
                r"(?i)stack\s*trace",
                r"(?i)error\s*dump",
                r"(?i)debug\s*info",
                r"(?i)development\s*server",
                # Common development phrases
                r"Hello\s+World",
                r"Test\s+Page",
                r"Development\s+Environment",
                r"Staging\s+Environment",
                r"Coming\s+Soon",
                r"Under\s+Construction",
                r"Work\s+in\s+Progress",
            ],
            "response_indicators": [
                # Headers
                "x-debug",
                "x-dev",
                "x-development",
                "x-staging",
                "x-test",
                "server: development",
                "server: staging",
                "server: test",
                "x-powered-by: dev",
                "x-environment: dev",
                # Status codes for dev environments
                [200, 403, 404, 500],  # Dev environments often return these
            ],
        }

    async def init_session(self):
        """Initialize aiohttp session"""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        )

    async def close_session(self):
        """Close session"""
        if self.session:
            await self.session.close()

    def generate_dev_targets(self, base_domain: str) -> List[str]:
        """Generate potential development targets from base domain"""
        targets = []
        parsed = urlparse(
            f"http://{base_domain}"
            if not base_domain.startswith("http")
            else base_domain
        )
        domain = parsed.netloc or parsed.path

        # Remove www if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Generate subdomain variants
        for subdomain in self.dev_patterns["dev_subdomains"]:
            targets.extend(
                [f"http://{subdomain}.{domain}", f"https://{subdomain}.{domain}"]
            )

        # Generate path variants for main domain
        base_urls = [f"http://{domain}", f"https://{domain}"]
        if not domain.startswith("www."):
            base_urls.extend([f"http://www.{domain}", f"https://www.{domain}"])

        for base_url in base_urls:
            for path in self.dev_patterns["dev_paths"]:
                targets.append(f"{base_url}{path}")
            for file in self.dev_patterns["dev_files"]:
                targets.append(f"{base_url}/{file}")

        return list(set(targets))  # Remove duplicates

    async def check_dev_interface(self, url: str) -> Dict:
        """Check if URL is a development interface"""
        if not self.session:
            await self.init_session()

        try:
            async with self.session.get(url, allow_redirects=True) as response:
                content = await response.text()
                headers = dict(response.headers)

                # Analyze response
                analysis = {
                    "url": url,
                    "status_code": response.status,
                    "is_dev_interface": False,
                    "confidence": 0,
                    "indicators": [],
                    "dev_info": {},
                    "headers": headers,
                    "content_length": len(content),
                }

                # Check content signatures
                dev_indicators = []
                confidence = 0

                for pattern in self.dev_patterns["content_signatures"]:
                    matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
                    if matches:
                        dev_indicators.append(
                            {
                                "type": "content_pattern",
                                "pattern": pattern,
                                "matches": matches,
                            }
                        )
                        confidence += 10

                # Check headers
                for header_key, header_value in headers.items():
                    header_key_lower = header_key.lower()
                    header_value_lower = str(header_value).lower()

                    dev_header_keywords = [
                        "dev",
                        "debug",
                        "test",
                        "staging",
                        "development",
                    ]
                    if any(
                        keyword in header_key_lower or keyword in header_value_lower
                        for keyword in dev_header_keywords
                    ):
                        dev_indicators.append(
                            {
                                "type": "header",
                                "header": f"{header_key}: {header_value}",
                            }
                        )
                        confidence += 15

                # Check URL path for dev keywords
                url_lower = url.lower()
                dev_keywords = [
                    "dev",
                    "test",
                    "staging",
                    "debug",
                    "development",
                    "demo",
                    "beta",
                    "alpha",
                ]
                for keyword in dev_keywords:
                    if keyword in url_lower:
                        dev_indicators.append(
                            {"type": "url_keyword", "keyword": keyword}
                        )
                        confidence += 5

                # Extract developer information
                dev_info = self.extract_dev_info(content)
                if dev_info:
                    confidence += 20
                    analysis["dev_info"] = dev_info

                # Special cases
                if response.status == 200 and len(content) < 1000:
                    # Likely a simple test page
                    confidence += 10

                if "Hello World" in content or "Test Page" in content:
                    confidence += 25

                # Final assessment
                analysis["indicators"] = dev_indicators
                analysis["confidence"] = min(confidence, 100)
                analysis["is_dev_interface"] = confidence >= 30

                return analysis

        except Exception as e:
            self.logger.debug(f"Error checking {url}: {e}")
            return {
                "url": url,
                "status_code": 0,
                "is_dev_interface": False,
                "confidence": 0,
                "indicators": [],
                "error": str(e),
            }

    def extract_dev_info(self, content: str) -> Dict:
        """Extract developer information from content"""
        dev_info = {}

        # Extract author information
        author_patterns = [
            r"@[Aa]utor?:?\s*([^\n\r]+)",
            r"[Aa]uthor:?\s*([^\n\r]+)",
            r"[Dd]eveloper:?\s*([^\n\r]+)",
            r"[Cc]reated\s+by:?\s*([^\n\r]+)",
        ]

        for pattern in author_patterns:
            matches = re.findall(pattern, content)
            if matches:
                dev_info["authors"] = list(set(matches))
                break

        # Extract dates
        date_patterns = [
            r"@[Dd]ate:?\s*([^\n\r]+)",
            r"@[Ll]ast[Ee]dit[Tt]ime:?\s*([^\n\r]+)",
            r"[Cc]reated:?\s*([^\n\r]+)",
            r"[Mm]odified:?\s*([^\n\r]+)",
        ]

        for pattern in date_patterns:
            matches = re.findall(pattern, content)
            if matches:
                dev_info["dates"] = list(set(matches))
                break

        # Extract version information
        version_patterns = [
            r"[Vv]ersion:?\s*([^\n\r]+)",
            r"v\d+\.\d+\.\d+",
            r"\d+\.\d+\.\d+",
        ]

        for pattern in version_patterns:
            matches = re.findall(pattern, content)
            if matches:
                dev_info["versions"] = list(set(matches))
                break

        # Extract environment information
        env_patterns = [
            r"[Ee]nvironment:?\s*([^\n\r]+)",
            r"[Mm]ode:?\s*([^\n\r]+)",
            r"NODE_ENV[=:]\s*([^\n\r\s]+)",
        ]

        for pattern in env_patterns:
            matches = re.findall(pattern, content)
            if matches:
                dev_info["environment"] = list(set(matches))
                break

        return dev_info

    async def hunt_dev_interfaces(
        self, domains: List[str], max_concurrent: int = 20
    ) -> List[Dict]:
        """Hunt for development interfaces across multiple domains"""
        await self.init_session()

        try:
            all_targets = []
            for domain in domains:
                targets = self.generate_dev_targets(domain)
                all_targets.extend(targets)

            self.logger.info(
                f"🔍 Hunting {len(all_targets)} potential dev interfaces..."
            )

            # Check all targets concurrently
            semaphore = asyncio.Semaphore(max_concurrent)

            async def check_with_semaphore(url):
                async with semaphore:
                    return await self.check_dev_interface(url)

            tasks = [check_with_semaphore(url) for url in all_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter successful results
            dev_interfaces = []
            for result in results:
                if isinstance(result, dict) and result.get("is_dev_interface", False):
                    dev_interfaces.append(result)

            # Sort by confidence
            dev_interfaces.sort(key=lambda x: x.get("confidence", 0), reverse=True)

            self.logger.info(f"🎯 Found {len(dev_interfaces)} development interfaces!")

            return dev_interfaces

        finally:
            await self.close_session()

    def save_dev_results(
        self, dev_interfaces: List[Dict], output_dir: str = "dev_hunt_results"
    ):
        """Save development interface hunting results"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Save JSON results
        with open(output_path / "dev_interfaces.json", "w") as f:
            json.dump(dev_interfaces, f, indent=2)

        # Save text summary
        with open(output_path / "dev_interfaces.txt", "w") as f:
            f.write("🔥 XSS Vibes V2 - Development Interface Discovery Report\n")
            f.write("=" * 60 + "\n\n")

            for interface in dev_interfaces:
                f.write(f"URL: {interface['url']}\n")
                f.write(f"Status: {interface['status_code']}\n")
                f.write(f"Confidence: {interface['confidence']}%\n")

                if interface.get("dev_info"):
                    f.write("Developer Info:\n")
                    for key, value in interface["dev_info"].items():
                        f.write(f"  {key}: {value}\n")

                f.write(f"Indicators: {len(interface.get('indicators', []))}\n")
                for indicator in interface.get("indicators", []):
                    f.write(f"  - {indicator}\n")

                f.write("-" * 40 + "\n")

        # Generate HTML report
        self.generate_dev_html_report(dev_interfaces, output_path)

        self.logger.info(f"📊 Results saved to {output_path}")

    def generate_dev_html_report(self, dev_interfaces: List[Dict], output_path: Path):
        """Generate HTML report for dev interface hunting"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vibes V2 - Development Interface Hunter</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; text-align: center; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .interface {{ background: white; margin: 15px 0; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .high-confidence {{ border-left: 5px solid #e53e3e; }}
                .medium-confidence {{ border-left: 5px solid #dd6b20; }}
                .low-confidence {{ border-left: 5px solid #38a169; }}
                .url {{ font-size: 1.2em; font-weight: bold; color: #2d3748; margin-bottom: 10px; }}
                .confidence {{ display: inline-block; padding: 5px 10px; border-radius: 20px; color: white; font-weight: bold; }}
                .high {{ background: #e53e3e; }}
                .medium {{ background: #dd6b20; }}
                .low {{ background: #38a169; }}
                .dev-info {{ background: #f7fafc; padding: 15px; border-radius: 8px; margin: 10px 0; }}
                .indicators {{ margin: 10px 0; }}
                .indicator {{ background: #e6fffa; padding: 8px; margin: 5px 0; border-radius: 5px; border-left: 3px solid #38b2ac; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 XSS Vibes V2 - Development Interface Hunter</h1>
                <p>Specialized reconnaissance for development environments</p>
                <p>Report generated: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <h3>{len(dev_interfaces)}</h3>
                    <p>Dev Interfaces Found</p>
                </div>
                <div class="stat">
                    <h3>{len([i for i in dev_interfaces if i.get('confidence', 0) >= 70])}</h3>
                    <p>High Confidence</p>
                </div>
                <div class="stat">
                    <h3>{len([i for i in dev_interfaces if i.get('dev_info')])}</h3>
                    <p>With Dev Info</p>
                </div>
                <div class="stat">
                    <h3>{len(set([i['url'].split('/')[2] for i in dev_interfaces if '/' in i['url']]))}</h3>
                    <p>Unique Domains</p>
                </div>
            </div>
        """

        for interface in dev_interfaces:
            confidence = interface.get("confidence", 0)
            confidence_class = (
                "high" if confidence >= 70 else "medium" if confidence >= 40 else "low"
            )
            interface_class = f"{confidence_class}-confidence"

            html_content += f"""
            <div class="interface {interface_class}">
                <div class="url">{interface['url']}</div>
                <span class="confidence {confidence_class}">{confidence}% confidence</span>
                <span style="margin-left: 10px; color: #666;">Status: {interface.get('status_code', 'N/A')}</span>
                
                {f'''
                <div class="dev-info">
                    <h4>🔧 Developer Information</h4>
                    {chr(10).join([f"<p><strong>{k.title()}:</strong> {v}</p>" for k, v in interface.get('dev_info', {}).items()])}
                </div>
                ''' if interface.get('dev_info') else ''}
                
                <div class="indicators">
                    <h4>📋 Detection Indicators ({len(interface.get('indicators', []))})</h4>
                    {chr(10).join([f'<div class="indicator">{indicator}</div>' for indicator in interface.get('indicators', [])])}
                </div>
            </div>
            """

        html_content += """
        </body>
        </html>
        """

        with open(output_path / "dev_interfaces.html", "w") as f:
            f.write(html_content)


async def main():
    """Main function for testing"""
    hunter = DevInterfaceHunter()

    # Example usage
    domains = ["trip.com", "example.com"]
    results = await hunter.hunt_dev_interfaces(domains)
    hunter.save_dev_results(results)

    print(f"🎯 Found {len(results)} development interfaces")
    for result in results[:5]:  # Show top 5
        print(f"  {result['url']} - {result['confidence']}% confidence")


if __name__ == "__main__":
    asyncio.run(main())
