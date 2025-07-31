#!/usr/bin/env python3
"""
XSS Vibes V2 - Osmedeus-style Endpoint Hunter
Advanced reconnaissance and vulnerability discovery
"""

import os
import sys
import json
import asyncio
import argparse
from pathlib import Path
from typing import List, Dict
import logging

# Add tools directory to path
sys.path.append(str(Path(__file__).parent))
sys.path.append(str(Path(__file__).parent.parent))

try:
    from advanced_crawler import AdvancedCrawler
    from xss_vibes.dev_hunter import DevInterfaceHunter
    from xss_vibes.api_hunter import APIEndpointHunter
except ImportError:
    print("❌ Error: advanced_crawler.py not found")
    sys.exit(1)


class EndpointHunter:
    """Osmedeus-style endpoint hunting orchestrator"""

    def __init__(self, workspace: str = "default"):
        self.workspace = workspace
        self.base_dir = Path("workspaces") / workspace
        self.setup_workspace()
        self.setup_logging()

    def setup_workspace(self):
        """Setup workspace directory structure"""
        directories = [
            self.base_dir,
            self.base_dir / "reconnaissance",
            self.base_dir / "crawling",
            self.base_dir / "vulnerabilities",
            self.base_dir / "reports",
            self.base_dir / "logs",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def setup_logging(self):
        """Setup workspace logging"""
        log_file = self.base_dir / "logs" / "endpoint_hunter.log"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

    def reconnaissance_phase(
        self, domain: str = None, fofa_query: str = None, shodan_query: str = None
    ):
        """Phase 1: Target discovery and reconnaissance"""
        self.logger.info("🔍 Starting reconnaissance phase...")

        results = {
            "targets": [],
            "fofa_results": [],
            "shodan_results": [],
            "dev_interfaces": [],
        }

        # Standard target discovery
        if domain:
            self.logger.info(f"🎯 Target domain: {domain}")
            results["targets"].append({"domain": domain, "type": "primary"})

            # Add API endpoint hunting
            self.logger.info("🔍 Hunting for API endpoints...")
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                api_hunter = APIEndpointHunter()
                api_endpoints = loop.run_until_complete(
                    api_hunter.hunt_api_endpoints([domain], max_concurrent=10)
                )
                results["api_endpoints"] = api_endpoints
                loop.close()

                self.logger.info(f"✅ Found {len(api_endpoints)} API endpoints")

                # Save API results
                api_output_dir = self.workspace_dir / "api_endpoints"
                api_hunter.save_api_results(api_endpoints, str(api_output_dir))

            except Exception as e:
                self.logger.error(f"API endpoint hunting failed: {e}")

            # Add dev interface hunting
            self.logger.info("🔍 Hunting for development interfaces...")
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                dev_hunter = DevInterfaceHunter()
                dev_interfaces = loop.run_until_complete(
                    dev_hunter.hunt_dev_interfaces([domain], max_concurrent=10)
                )
                results["dev_interfaces"] = dev_interfaces
                loop.close()

                self.logger.info(
                    f"✅ Found {len(dev_interfaces)} development interfaces"
                )

                # Save dev interface results
                dev_output_dir = self.workspace_dir / "dev_interfaces"
                dev_hunter.save_dev_results(dev_interfaces, str(dev_output_dir))

            except Exception as e:
                self.logger.error(f"Dev interface hunting failed: {e}")

        # Save reconnaissance results
        recon_file = self.workspace_dir / "reconnaissance.json"
        with open(recon_file, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info("✅ Reconnaissance phase completed")
        return results

    async def crawling_phase(self, target_urls: List[str]):
        """Phase 2: Advanced endpoint crawling"""
        self.logger.info("🕷️ Phase 2: Advanced Endpoint Crawling")

        config_file = "config/crawler_config.yaml"
        output_dir = self.base_dir / "crawling"

        crawler = AdvancedCrawler(config_file)
        crawler.config["output"]["directory"] = str(output_dir)

        await crawler.init_session()

        try:
            all_endpoints = set()
            semaphore = asyncio.Semaphore(crawler.config["crawling"]["threads"])

            async def crawl_target(url):
                async with semaphore:
                    self.logger.info(f"🔍 Crawling: {url}")
                    endpoints = await crawler.crawl_endpoints(url)
                    return endpoints

            # Crawl all targets
            tasks = [
                crawl_target(url) for url in target_urls[:100]
            ]  # Limit to 100 URLs
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, set):
                    all_endpoints.update(result)

            # Save crawling results
            endpoints_file = output_dir / "endpoints.txt"
            with open(endpoints_file, "w") as f:
                for endpoint in sorted(all_endpoints):
                    f.write(f"{endpoint}\n")

            endpoints_json = output_dir / "endpoints.json"
            with open(endpoints_json, "w") as f:
                json.dump(list(all_endpoints), f, indent=2)

            self.logger.info(
                f"🕷️ Crawling complete: {len(all_endpoints)} endpoints discovered"
            )
            return list(all_endpoints)

        finally:
            await crawler.close_session()

    def vulnerability_scan_phase(self, endpoints: List[str]):
        """Phase 3: Vulnerability scanning"""
        self.logger.info("🔥 Phase 3: Vulnerability Scanning")

        output_dir = self.base_dir / "vulnerabilities"

        # Prepare endpoints file
        endpoints_file = output_dir / "targets.txt"
        with open(endpoints_file, "w") as f:
            for endpoint in endpoints:
                f.write(f"{endpoint}\n")

        config_file = "config/crawler_config.yaml"
        crawler = AdvancedCrawler(config_file)

        vulnerabilities = []

        # Nuclei scan
        self.logger.info("🚀 Running Nuclei scan...")
        nuclei_vulns = crawler.run_nuclei_scan(str(endpoints_file))
        vulnerabilities.extend(nuclei_vulns)

        # Jaeles scan
        self.logger.info("⚔️ Running Jaeles scan...")
        jaeles_vulns = crawler.run_jaeles_scan(str(endpoints_file))
        vulnerabilities.extend(jaeles_vulns)

        # Save vulnerability results
        vulns_file = output_dir / "vulnerabilities.json"
        with open(vulns_file, "w") as f:
            json.dump(vulnerabilities, f, indent=2)

        self.logger.info(
            f"🔥 Vulnerability scan complete: {len(vulnerabilities)} vulnerabilities found"
        )
        return vulnerabilities

    def generate_final_report(
        self, targets: List[str], endpoints: List[str], vulnerabilities: List[Dict]
    ):
        """Phase 4: Generate comprehensive report"""
        self.logger.info("📊 Phase 4: Generating Final Report")

        reports_dir = self.base_dir / "reports"

        # Summary statistics
        stats = {
            "workspace": self.workspace,
            "targets_count": len(targets),
            "endpoints_count": len(endpoints),
            "vulnerabilities_count": len(vulnerabilities),
            "critical_vulns": len(
                [
                    v
                    for v in vulnerabilities
                    if v.get("info", {}).get("severity") == "critical"
                ]
            ),
            "high_vulns": len(
                [
                    v
                    for v in vulnerabilities
                    if v.get("info", {}).get("severity") == "high"
                ]
            ),
            "medium_vulns": len(
                [
                    v
                    for v in vulnerabilities
                    if v.get("info", {}).get("severity") == "medium"
                ]
            ),
            "low_vulns": len(
                [
                    v
                    for v in vulnerabilities
                    if v.get("info", {}).get("severity") == "low"
                ]
            ),
        }

        # Save summary
        summary_file = reports_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(stats, f, indent=2)

        # Generate HTML report
        self.generate_html_report(stats, vulnerabilities, reports_dir)

        # Print summary
        print("\n" + "=" * 60)
        print(f"🎯 XSS Vibes V2 - Endpoint Hunter Summary")
        print("=" * 60)
        print(f"📂 Workspace: {self.workspace}")
        print(f"🎯 Targets: {stats['targets_count']}")
        print(f"🕷️ Endpoints: {stats['endpoints_count']}")
        print(f"🔥 Total Vulnerabilities: {stats['vulnerabilities_count']}")
        print(f"   🚨 Critical: {stats['critical_vulns']}")
        print(f"   🟠 High: {stats['high_vulns']}")
        print(f"   🟡 Medium: {stats['medium_vulns']}")
        print(f"   🔵 Low: {stats['low_vulns']}")
        print(f"📊 Report: {reports_dir / 'report.html'}")
        print("=" * 60)

    def generate_html_report(
        self, stats: Dict, vulnerabilities: List[Dict], output_dir: Path
    ):
        """Generate detailed HTML report"""

        # Group vulnerabilities by severity
        vuln_groups = {
            "critical": [
                v
                for v in vulnerabilities
                if v.get("info", {}).get("severity") == "critical"
            ],
            "high": [
                v
                for v in vulnerabilities
                if v.get("info", {}).get("severity") == "high"
            ],
            "medium": [
                v
                for v in vulnerabilities
                if v.get("info", {}).get("severity") == "medium"
            ],
            "low": [
                v for v in vulnerabilities if v.get("info", {}).get("severity") == "low"
            ],
        }

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vibes V2 - Endpoint Hunter Report</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
                .stat-number {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
                .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .vulnerability {{ margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid; }}
                .critical {{ background: #fed7d7; border-color: #e53e3e; }}
                .high {{ background: #feebc8; border-color: #dd6b20; }}
                .medium {{ background: #fef5e7; border-color: #d69e2e; }}
                .low {{ background: #f0fff4; border-color: #38a169; }}
                .vuln-title {{ font-weight: bold; font-size: 1.1em; }}
                .vuln-url {{ color: #666; font-family: monospace; }}
                h2 {{ color: #2d3748; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔥 XSS Vibes V2 - Endpoint Hunter</h1>
                <p>Advanced Reconnaissance & Vulnerability Discovery Report</p>
                <p>Workspace: <strong>{stats['workspace']}</strong></p>
            </div>
            
            <div class="container">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{stats['targets_count']}</div>
                        <div>Targets Discovered</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['endpoints_count']}</div>
                        <div>Endpoints Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['vulnerabilities_count']}</div>
                        <div>Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['critical_vulns']}</div>
                        <div>Critical Issues</div>
                    </div>
                </div>
        """

        # Add vulnerability sections
        severity_colors = {
            "critical": ("🚨 Critical Vulnerabilities", "critical"),
            "high": ("🟠 High Severity Vulnerabilities", "high"),
            "medium": ("🟡 Medium Severity Vulnerabilities", "medium"),
            "low": ("🔵 Low Severity Vulnerabilities", "low"),
        }

        for severity, (title, css_class) in severity_colors.items():
            vulns = vuln_groups.get(severity, [])
            if vulns:
                html_content += f"""
                <div class="section">
                    <h2>{title} ({len(vulns)})</h2>
                """

                for vuln in vulns[:20]:  # Limit to 20 per severity
                    template_id = vuln.get("template-id", "Unknown")
                    matched_at = vuln.get("matched-at", "Unknown URL")
                    info = vuln.get("info", {})
                    description = info.get("description", "No description available")

                    html_content += f"""
                    <div class="vulnerability {css_class}">
                        <div class="vuln-title">{template_id}</div>
                        <div class="vuln-url">{matched_at}</div>
                        <div>{description}</div>
                    </div>
                    """

                html_content += "</div>"

        html_content += """
            </div>
        </body>
        </html>
        """

        report_file = output_dir / "report.html"
        with open(report_file, "w") as f:
            f.write(html_content)

    async def run_full_scan(
        self,
        domain: str = None,
        fofa_query: str = None,
        shodan_query: str = None,
        target_urls: List[str] = None,
    ):
        """Run complete endpoint hunting pipeline"""

        # Phase 1: Reconnaissance
        if target_urls:
            targets = target_urls
        else:
            targets = self.reconnaissance_phase(domain, fofa_query, shodan_query)

        if not targets:
            self.logger.error("❌ No targets found in reconnaissance phase")
            return

        # Phase 2: Crawling
        endpoints = await self.crawling_phase(targets)

        if not endpoints:
            self.logger.error("❌ No endpoints discovered in crawling phase")
            return

        # Phase 3: Vulnerability Scanning
        vulnerabilities = self.vulnerability_scan_phase(endpoints)

        # Phase 4: Report Generation
        self.generate_final_report(targets, endpoints, vulnerabilities)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="XSS Vibes V2 - Osmedeus-style Endpoint Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hunt endpoints for a domain
  python3 endpoint_hunter.py -d example.com -w example_scan
  
  # Use custom Fofa query
  python3 endpoint_hunter.py -f 'title="admin panel"' -w admin_hunt
  
  # Use custom Shodan query  
  python3 endpoint_hunter.py -s 'http.title:login' -w login_hunt
  
  # Hunt specific URLs
  python3 endpoint_hunter.py -t https://example.com https://test.com -w direct_scan
  
  # Combined reconnaissance
  python3 endpoint_hunter.py -d example.com -f 'domain="example.com"' -s 'hostname:example.com' -w full_scan
        """,
    )

    parser.add_argument("-d", "--domain", help="Target domain for reconnaissance")
    parser.add_argument("-f", "--fofa", help="Custom Fofa search query")
    parser.add_argument("-s", "--shodan", help="Custom Shodan search query")
    parser.add_argument("-t", "--targets", nargs="+", help="Direct target URLs")
    parser.add_argument("-w", "--workspace", default="default", help="Workspace name")

    args = parser.parse_args()

    if not any([args.domain, args.fofa, args.shodan, args.targets]):
        parser.error("❌ Must specify at least one of: -d, -f, -s, or -t")

    # Create hunter instance
    hunter = EndpointHunter(args.workspace)

    # Run full scan
    asyncio.run(
        hunter.run_full_scan(
            domain=args.domain,
            fofa_query=args.fofa,
            shodan_query=args.shodan,
            target_urls=args.targets,
        )
    )


if __name__ == "__main__":
    main()
