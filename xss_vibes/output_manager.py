"""Output management for scan results."""

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from .models import ScanResult, VulnerabilityResult, VulnerabilityLevel


logger = logging.getLogger("xss_vibes.output")


class OutputManager:
    """Manages output formatting and saving."""

    def __init__(self, output_file: Optional[Path] = None):
        """
        Initialize output manager.

        Args:
            output_file: Path to output file
        """
        self.output_file = output_file

    def save_results(self, results: List[ScanResult]) -> None:
        """
        Save scan results to file.

        Args:
            results: List of scan results to save
        """
        if not self.output_file:
            return

        try:
            # Collect all vulnerabilities
            vulnerabilities = []
            for result in results:
                for vuln in result.vulnerabilities:
                    vulnerabilities.append(self._format_vulnerability_for_output(vuln))

            # Write to file
            with open(self.output_file, "w", encoding="utf-8") as f:
                for vuln in vulnerabilities:
                    f.write(f"{vuln}\n")

            logger.info(
                f"Saved {len(vulnerabilities)} vulnerabilities to {self.output_file}"
            )

        except Exception as e:
            logger.error(f"Error saving results to {self.output_file}: {e}")

    def save_results_json(
        self, results: List[ScanResult], output_file: Optional[Path] = None
    ) -> None:
        """
        Save scan results in JSON format.

        Args:
            results: List of scan results to save
            output_file: Optional output file path
        """
        output_path = output_file or self.output_file
        if not output_path:
            return

        # Ensure .json extension
        if not str(output_path).endswith(".json"):
            output_path = Path(str(output_path) + ".json")

        try:
            report_data = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "total_targets": len(results),
                    "vulnerable_targets": len([r for r in results if r.is_vulnerable]),
                    "total_vulnerabilities": sum(
                        len(r.vulnerabilities) for r in results
                    ),
                },
                "results": [result.to_dict() for result in results],
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved detailed results to {output_path}")

        except Exception as e:
            logger.error(f"Error saving JSON results: {e}")

    def _format_vulnerability_for_output(self, vuln: VulnerabilityResult) -> str:
        """Format vulnerability for text output."""
        # Replace parameter in URL with payload
        from url_utils import URLProcessor

        vulnerable_url = URLProcessor.replace_parameter_value(
            vuln.url, vuln.parameter, vuln.payload
        )
        return vulnerable_url

    def print_summary(self, results: List[ScanResult]) -> None:
        """
        Print summary of scan results.

        Args:
            results: List of scan results
        """
        total_targets = len(results)
        vulnerable_targets = [r for r in results if r.is_vulnerable]
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in results)

        logger.info(f"\n{'='*50}")
        logger.info("SCAN SUMMARY")
        logger.info(f"{'='*50}")
        logger.info(f"Total targets scanned: {total_targets}")
        logger.info(f"Vulnerable targets: {len(vulnerable_targets)}")
        logger.info(f"Total vulnerabilities: {total_vulnerabilities}")

        if vulnerable_targets:
            logger.warning("\nVULNERABLE TARGETS:")
            for result in vulnerable_targets:
                logger.warning(
                    f"  {result.target.url} ({len(result.vulnerabilities)} vulns)"
                )

                for vuln in result.vulnerabilities:
                    vulnerable_url = self._format_vulnerability_for_output(vuln)
                    logger.warning(f"    Parameter: {vuln.parameter}")
                    logger.warning(f"    Payload: {vuln.payload}")
                    logger.warning(f"    URL: {vulnerable_url}")
                    logger.warning(f"    Level: {vuln.level.value.upper()}")
                    logger.warning("")

        logger.info(f"{'='*50}")

    def print_results_console(self, results: List[ScanResult]) -> None:
        """
        Print results to console in real-time format.

        Args:
            results: List of scan results
        """
        for result in results:
            if result.target.status.value == "error":
                logger.error(
                    f"ERROR scanning {result.target.url}: {', '.join(result.errors)}"
                )
            elif result.is_vulnerable:
                logger.warning(f"VULNERABLE: {result.target.url}")
                for vuln in result.vulnerabilities:
                    vulnerable_url = self._format_vulnerability_for_output(vuln)
                    logger.warning(f"  Parameter: {vuln.parameter}")
                    logger.warning(f"  Payload: {vuln.payload}")
                    logger.warning(f"  URL: {vulnerable_url}")
            else:
                logger.info(f"SAFE: {result.target.url}")


class ReportGenerator:
    """Generate detailed reports from scan results."""

    @staticmethod
    def generate_html_report(results: List[ScanResult], output_file: Path) -> None:
        """
        Generate HTML report.

        Args:
            results: Scan results
            output_file: Output HTML file path
        """
        try:
            html_content = ReportGenerator._create_html_content(results)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")

    @staticmethod
    def _create_html_content(results: List[ScanResult]) -> str:
        """Create HTML content for the report."""
        total_targets = len(results)
        vulnerable_targets = [r for r in results if r.is_vulnerable]
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in results)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Vibes Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .vulnerable {{ color: #d9534f; }}
        .safe {{ color: #5cb85c; }}
        .error {{ color: #f0ad4e; }}
        .vulnerability {{ 
            border: 1px solid #ddd; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 5px; 
            background-color: #fff5f5;
        }}
        .url {{ font-family: monospace; background-color: #f8f8f8; padding: 5px; }}
        .payload {{ font-family: monospace; background-color: #fffacd; padding: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>XSS Vibes Scan Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Total targets scanned: {total_targets}</li>
            <li>Vulnerable targets: <span class="vulnerable">{len(vulnerable_targets)}</span></li>
            <li>Total vulnerabilities: <span class="vulnerable">{total_vulnerabilities}</span></li>
        </ul>
    </div>
    
    <div class="results">
        <h2>Detailed Results</h2>
"""

        for result in results:
            status_class = "vulnerable" if result.is_vulnerable else "safe"
            if result.target.status.value == "error":
                status_class = "error"

            html += f"""
        <div class="target">
            <h3 class="{status_class}">Target: {result.target.url}</h3>
            <p>Status: {result.target.status.value.upper()}</p>
            
"""

            if result.vulnerabilities:
                html += "            <h4>Vulnerabilities Found:</h4>\n"
                for vuln in result.vulnerabilities:
                    from url_utils import URLProcessor

                    vulnerable_url = URLProcessor.replace_parameter_value(
                        vuln.url, vuln.parameter, vuln.payload
                    )

                    html += f"""
            <div class="vulnerability">
                <p><strong>Parameter:</strong> {vuln.parameter}</p>
                <p><strong>Payload:</strong> <span class="payload">{vuln.payload}</span></p>
                <p><strong>Vulnerable URL:</strong> <span class="url">{vulnerable_url}</span></p>
                <p><strong>Severity:</strong> {vuln.level.value.upper()}</p>
            </div>
"""

            if result.errors:
                html += f"            <p><strong>Errors:</strong> {', '.join(result.errors)}</p>\n"

            html += "        </div>\n"

        html += """
    </div>
</body>
</html>
"""

        return html
