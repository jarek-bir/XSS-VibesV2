"""Advanced reporting system for XSS scanner results."""

import json
import csv

# Use defusedxml for secure XML parsing
try:
    import defusedxml.ElementTree as ET
except ImportError:
    # Fallback to standard library with warning
    import xml.etree.ElementTree as ET
    import warnings

    warnings.warn(
        "defusedxml not available. Consider installing for better security.",
        UserWarning,
        stacklevel=2,
    )
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from jinja2 import Template
import logging

from .models import ScanResult, VulnerabilityLevel


logger = logging.getLogger("xss_vibes.reporting")


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    include_payloads: bool = True
    include_screenshots: bool = False
    include_recommendations: bool = True
    include_technical_details: bool = True
    severity_filter: Optional[VulnerabilityLevel] = None
    custom_logo: Optional[str] = None
    custom_footer: Optional[str] = None


class AdvancedReporter:
    """Advanced reporting system with multiple output formats."""

    def __init__(self, config: Optional[ReportConfig] = None):
        """Initialize reporter with configuration."""
        self.config = config or ReportConfig()
        self.report_templates = self._load_templates()

    def generate_comprehensive_report(
        self,
        results: List[ScanResult],
        output_path: Path,
        format_type: str = "html",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Generate comprehensive security report.

        Args:
            results: Scan results
            output_path: Output file path
            format_type: Format (html, pdf, json, xml, csv, markdown)
            metadata: Additional metadata for report

        Returns:
            Success status
        """
        try:
            # Prepare report data
            report_data = self._prepare_report_data(results, metadata)

            # Generate report based on format
            if format_type.lower() == "html":
                return self._generate_html_report(report_data, output_path)
            elif format_type.lower() == "pdf":
                # PDF generation would require additional dependencies
                raise ValueError(
                    "PDF generation not implemented. Install reportlab for PDF support."
                )
            elif format_type.lower() == "json":
                return self._generate_json_report(report_data, output_path)
            elif format_type.lower() == "xml":
                # XML generation would require additional dependencies
                raise ValueError("XML generation not implemented.")
            elif format_type.lower() == "csv":
                return self._generate_csv_report(report_data, output_path)
            elif format_type.lower() == "markdown":
                return self._generate_markdown_report(report_data, output_path)
            else:
                logger.error(f"Unsupported format: {format_type}")
                return False

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return False

    def _prepare_report_data(
        self, results: List[ScanResult], metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Prepare comprehensive report data."""

        # Filter results by severity if configured
        if self.config.severity_filter:
            results = [
                r
                for r in results
                if r.vulnerability_level == self.config.severity_filter
            ]

        # Calculate statistics
        stats = self._calculate_statistics(results)

        # Group results by various criteria
        grouped_results = self._group_results(results)

        # Generate security summary
        security_summary = self._generate_security_summary(results)

        # Prepare vulnerability details
        vulnerability_details = self._prepare_vulnerability_details(results)

        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "XSS Vibes v2.0.0",
                "total_vulnerabilities": len(results),
                **(metadata or {}),
            },
            "statistics": stats,
            "security_summary": security_summary,
            "grouped_results": grouped_results,
            "vulnerability_details": vulnerability_details,
            "recommendations": self._generate_recommendations(results),
            "technical_appendix": (
                self._generate_technical_appendix(results)
                if self.config.include_technical_details
                else None
            ),
        }

        return report_data

    def _calculate_statistics(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate comprehensive statistics."""

        if not results:
            return {"total": 0, "by_severity": {}, "by_context": {}, "success_rate": 0}

        # Count by severity
        severity_counts = {}
        for level in VulnerabilityLevel:
            severity_counts[level.value] = len(
                [r for r in results if r.vulnerability_level == level]
            )

        # Count by context
        context_counts = {}
        for result in results:
            context = getattr(result, "context", "unknown")
            context_counts[context] = context_counts.get(context, 0) + 1

        # Count by URL
        url_counts = {}
        for result in results:
            url_counts[result.url] = url_counts.get(result.url, 0) + 1

        # Calculate success rates
        vulnerable_count = len([r for r in results if r.status.value == "vulnerable"])
        total_tests = len(results) if results else 1
        success_rate = (vulnerable_count / total_tests) * 100

        return {
            "total": len(results),
            "vulnerable_count": vulnerable_count,
            "success_rate": round(success_rate, 2),
            "by_severity": severity_counts,
            "by_context": context_counts,
            "by_url": url_counts,
            "unique_urls": len(set(r.url for r in results)),
            "avg_response_time": self._calculate_avg_response_time(results),
        }

    def _group_results(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Group results by various criteria."""

        grouped = {
            "by_severity": {},
            "by_url": {},
            "by_parameter": {},
            "by_payload_type": {},
        }

        # Group by severity
        for level in VulnerabilityLevel:
            grouped["by_severity"][level.value] = [
                r for r in results if r.vulnerability_level == level
            ]

        # Group by URL
        for result in results:
            url = result.url
            if url not in grouped["by_url"]:
                grouped["by_url"][url] = []
            grouped["by_url"][url].append(result)

        # Group by parameter
        for result in results:
            param = getattr(result, "parameter", "unknown")
            if param not in grouped["by_parameter"]:
                grouped["by_parameter"][param] = []
            grouped["by_parameter"][param].append(result)

        return grouped

    def _generate_security_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate executive security summary."""

        if not results:
            return {
                "risk_level": "Unknown",
                "critical_findings": 0,
                "recommendation": "No vulnerabilities found",
            }

        # Calculate risk level
        critical_count = len(
            [r for r in results if r.vulnerability_level == VulnerabilityLevel.CRITICAL]
        )
        high_count = len(
            [r for r in results if r.vulnerability_level == VulnerabilityLevel.HIGH]
        )

        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 2:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Generate key findings
        key_findings = []
        if critical_count > 0:
            key_findings.append(
                f"{critical_count} critical XSS vulnerabilities requiring immediate attention"
            )
        if high_count > 0:
            key_findings.append(f"{high_count} high-severity XSS vulnerabilities")

        # Most affected URLs
        url_counts = {}
        for result in results:
            url_counts[result.url] = url_counts.get(result.url, 0) + 1

        most_affected = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:3]

        return {
            "risk_level": risk_level,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "key_findings": key_findings,
            "most_affected_urls": most_affected,
            "recommendation": self._get_risk_recommendation(risk_level),
        }

    def _prepare_vulnerability_details(
        self, results: List[ScanResult]
    ) -> List[Dict[str, Any]]:
        """Prepare detailed vulnerability information."""

        details = []
        for result in results:
            detail = {
                "id": f"XSS-{hash(result.url + str(result.payload))%10000:04d}",
                "url": result.url,
                "parameter": getattr(result, "parameter", "N/A"),
                "payload": (
                    result.payload if self.config.include_payloads else "[REDACTED]"
                ),
                "severity": (
                    result.vulnerability_level.value
                    if result.vulnerability_level
                    else "unknown"
                ),
                "context": getattr(result, "context", "unknown"),
                "description": self._generate_vulnerability_description(result),
                "impact": self._generate_impact_description(result),
                "remediation": self._generate_remediation_steps(result),
                "technical_details": (
                    self._generate_technical_details(result)
                    if self.config.include_technical_details
                    else None
                ),
            }
            details.append(detail)

        return details

    def _generate_recommendations(
        self, results: List[ScanResult]
    ) -> List[Dict[str, Any]]:
        """Generate security recommendations."""

        recommendations = [
            {
                "priority": "HIGH",
                "category": "Input Validation",
                "title": "Implement Proper Input Validation",
                "description": "Validate and sanitize all user inputs on both client and server side",
                "implementation": [
                    "Use whitelist-based input validation",
                    "Implement proper data type validation",
                    "Reject or sanitize special characters",
                    "Use parameterized queries for database operations",
                ],
            },
            {
                "priority": "HIGH",
                "category": "Output Encoding",
                "title": "Implement Context-Aware Output Encoding",
                "description": "Encode all dynamic content based on output context",
                "implementation": [
                    "HTML encode data in HTML context",
                    "JavaScript encode data in JS context",
                    "URL encode data in URL context",
                    "CSS encode data in CSS context",
                ],
            },
            {
                "priority": "MEDIUM",
                "category": "Security Headers",
                "title": "Deploy Security Headers",
                "description": "Implement security headers to provide defense in depth",
                "implementation": [
                    "Content-Security-Policy (CSP)",
                    "X-XSS-Protection: 1; mode=block",
                    "X-Content-Type-Options: nosniff",
                    "X-Frame-Options: DENY",
                ],
            },
        ]

        # Add specific recommendations based on findings
        if results:
            critical_count = len(
                [
                    r
                    for r in results
                    if r.vulnerability_level == VulnerabilityLevel.CRITICAL
                ]
            )
            if critical_count > 0:
                recommendations.insert(
                    0,
                    {
                        "priority": "CRITICAL",
                        "category": "Immediate Action",
                        "title": "Address Critical Vulnerabilities Immediately",
                        "description": f"Found {critical_count} critical XSS vulnerabilities requiring immediate remediation",
                        "implementation": [
                            "Review and fix all critical findings within 24 hours",
                            "Deploy emergency patches if necessary",
                            "Monitor affected endpoints closely",
                            "Consider temporary disabling of vulnerable features if fix is not immediately available",
                        ],
                    },
                )

        return recommendations

    def _generate_html_report(
        self, report_data: Dict[str, Any], output_path: Path
    ) -> bool:
        """Generate HTML report."""

        html_template = self.report_templates.get(
            "html", self._get_default_html_template()
        )

        try:
            template = Template(html_template)
            html_content = template.render(**report_data, config=self.config)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_path}")
            return True

        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            return False

    def _generate_json_report(
        self, report_data: Dict[str, Any], output_path: Path
    ) -> bool:
        """Generate JSON report."""

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info(f"JSON report generated: {output_path}")
            return True

        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            return False

    def _generate_csv_report(
        self, report_data: Dict[str, Any], output_path: Path
    ) -> bool:
        """Generate CSV report."""

        try:
            vulnerability_details = report_data.get("vulnerability_details", [])

            if not vulnerability_details:
                logger.warning("No vulnerability details to export to CSV")
                return False

            fieldnames = [
                "id",
                "url",
                "parameter",
                "severity",
                "context",
                "description",
                "payload",
            ]

            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for vuln in vulnerability_details:
                    row = {field: vuln.get(field, "") for field in fieldnames}
                    writer.writerow(row)

            logger.info(f"CSV report generated: {output_path}")
            return True

        except Exception as e:
            logger.error(f"CSV report generation failed: {e}")
            return False

    def _generate_markdown_report(
        self, report_data: Dict[str, Any], output_path: Path
    ) -> bool:
        """Generate Markdown report."""

        markdown_template = self.report_templates.get(
            "markdown", self._get_default_markdown_template()
        )

        try:
            template = Template(markdown_template)
            markdown_content = template.render(**report_data, config=self.config)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            logger.info(f"Markdown report generated: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Markdown report generation failed: {e}")
            return False

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates from files or use defaults."""
        templates = {}

        template_dir = Path(__file__).parent / "templates"
        if template_dir.exists():
            for template_file in template_dir.glob("*.html"):
                with open(template_file, "r", encoding="utf-8") as f:
                    templates[template_file.stem] = f.read()

        return templates

    def _get_default_html_template(self) -> str:
        """Get default HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #f39c12; font-weight: bold; }
        .medium { color: #f1c40f; font-weight: bold; }
        .low { color: #27ae60; font-weight: bold; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .payload { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ XSS Security Assessment Report</h1>
        <p>Generated: {{ metadata.generated_at }}</p>
        <p>Scanner: {{ metadata.scanner_version }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Risk Level:</strong> <span class="{{ security_summary.risk_level.lower() }}">{{ security_summary.risk_level }}</span></p>
        <p><strong>Total Vulnerabilities:</strong> {{ statistics.total }}</p>
        <p><strong>Critical Findings:</strong> {{ security_summary.critical_findings }}</p>
        <p><strong>High Findings:</strong> {{ security_summary.high_findings }}</p>
    </div>

    <h2>📊 Statistics</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Total Tests</td>
            <td>{{ statistics.total }}</td>
        </tr>
        <tr>
            <td>Vulnerable Endpoints</td>
            <td>{{ statistics.vulnerable_count }}</td>
        </tr>
        <tr>
            <td>Success Rate</td>
            <td>{{ statistics.success_rate }}%</td>
        </tr>
        <tr>
            <td>Unique URLs</td>
            <td>{{ statistics.unique_urls }}</td>
        </tr>
    </table>

    <h2>🚨 Vulnerability Details</h2>
    {% for vuln in vulnerability_details %}
    <div class="vulnerability">
        <h3>{{ vuln.id }} - <span class="{{ vuln.severity }}">{{ vuln.severity.upper() }}</span></h3>
        <p><strong>URL:</strong> {{ vuln.url }}</p>
        <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
        <p><strong>Context:</strong> {{ vuln.context }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if config.include_payloads %}
        <div class="payload">
            <strong>Payload:</strong> {{ vuln.payload }}
        </div>
        {% endif %}
        <p><strong>Impact:</strong> {{ vuln.impact }}</p>
        <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
    </div>
    {% endfor %}

    <h2>💡 Recommendations</h2>
    {% for rec in recommendations %}
    <div class="vulnerability">
        <h3>{{ rec.title }} ({{ rec.priority }})</h3>
        <p><strong>Category:</strong> {{ rec.category }}</p>
        <p>{{ rec.description }}</p>
        <ul>
        {% for step in rec.implementation %}
            <li>{{ step }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endfor %}

    <div class="summary">
        <p>Report generated by XSS Vibes v2.0.0 - Advanced XSS Scanner</p>
    </div>
</body>
</html>
        """

    def _get_default_markdown_template(self) -> str:
        """Get default Markdown template."""
        return """
# 🛡️ XSS Security Assessment Report

**Generated:** {{ metadata.generated_at }}  
**Scanner:** {{ metadata.scanner_version }}  

## Executive Summary

**Risk Level:** {{ security_summary.risk_level }}  
**Total Vulnerabilities:** {{ statistics.total }}  
**Critical Findings:** {{ security_summary.critical_findings }}  
**High Findings:** {{ security_summary.high_findings }}  

## 📊 Statistics

| Metric | Value |
|--------|--------|
| Total Tests | {{ statistics.total }} |
| Vulnerable Endpoints | {{ statistics.vulnerable_count }} |
| Success Rate | {{ statistics.success_rate }}% |
| Unique URLs | {{ statistics.unique_urls }} |

## 🚨 Vulnerability Details

{% for vuln in vulnerability_details %}
### {{ vuln.id }} - {{ vuln.severity.upper() }}

**URL:** {{ vuln.url }}  
**Parameter:** {{ vuln.parameter }}  
**Context:** {{ vuln.context }}  

**Description:** {{ vuln.description }}

{% if config.include_payloads %}
**Payload:**
```
{{ vuln.payload }}
```
{% endif %}

**Impact:** {{ vuln.impact }}

**Remediation:** {{ vuln.remediation }}

---
{% endfor %}

## 💡 Recommendations

{% for rec in recommendations %}
### {{ rec.title }} ({{ rec.priority }})

**Category:** {{ rec.category }}

{{ rec.description }}

{% for step in rec.implementation %}
- {{ step }}
{% endfor %}

{% endfor %}

---
*Report generated by XSS Vibes v2.0.0 - Advanced XSS Scanner*
        """

    # Helper methods for generating content

    def _calculate_avg_response_time(self, results: List[ScanResult]) -> float:
        """Calculate average response time."""
        times = [
            getattr(r, "response_time", 0)
            for r in results
            if hasattr(r, "response_time")
        ]
        return round(sum(times) / len(times), 2) if times else 0.0

    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            "CRITICAL": "Immediate action required. Fix critical vulnerabilities within 24 hours.",
            "HIGH": "High priority remediation needed within 1 week.",
            "MEDIUM": "Address vulnerabilities within 1 month.",
            "LOW": "Monitor and address as part of regular maintenance.",
            "Unknown": "Conduct thorough security assessment.",
        }
        return recommendations.get(risk_level, "Review security posture.")

    def _generate_vulnerability_description(self, result: ScanResult) -> str:
        """Generate vulnerability description."""
        return f"Cross-Site Scripting (XSS) vulnerability detected in parameter allowing execution of malicious scripts."

    def _generate_impact_description(self, result: ScanResult) -> str:
        """Generate impact description."""
        if result.vulnerability_level == VulnerabilityLevel.CRITICAL:
            return "Complete compromise of user session, data theft, account takeover possible."
        elif result.vulnerability_level == VulnerabilityLevel.HIGH:
            return "Session hijacking, data theft, defacement of web pages possible."
        elif result.vulnerability_level == VulnerabilityLevel.MEDIUM:
            return "Limited script execution, potential for phishing attacks."
        else:
            return "Minimal security impact, requires user interaction."

    def _generate_remediation_steps(self, result: ScanResult) -> str:
        """Generate remediation steps."""
        return "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers."

    def _generate_technical_details(self, result: ScanResult) -> Dict[str, Any]:
        """Generate technical details."""
        return {
            "http_method": getattr(result, "method", "GET"),
            "response_code": getattr(result, "response_code", 200),
            "content_type": getattr(result, "content_type", "text/html"),
            "payload_encoding": getattr(result, "payload_encoding", "none"),
        }

    def _generate_technical_appendix(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate technical appendix."""
        return {
            "scan_methodology": "Automated XSS testing using multiple payload vectors",
            "tools_used": ["XSS Vibes v2.0.0"],
            "test_coverage": f"{len(set(r.url for r in results))} unique endpoints tested",
            "payload_categories": "Reflected XSS, Stored XSS, DOM-based XSS",
        }


# Global instance
advanced_reporter = AdvancedReporter()


def generate_report(
    results: List[ScanResult],
    output_path: Path,
    format_type: str = "html",
    config: Optional[ReportConfig] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Convenience function for report generation."""

    if config:
        reporter = AdvancedReporter(config)
    else:
        reporter = advanced_reporter

    return reporter.generate_comprehensive_report(
        results, output_path, format_type, metadata
    )
