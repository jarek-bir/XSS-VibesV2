#!/usr/bin/env python3
"""Test advanced reporting functionality."""

from pathlib import Path
from xss_vibes.models import (
    ScanResult,
    ScanTarget,
    VulnerabilityResult,
    VulnerabilityLevel,
)
from xss_vibes.advanced_reporting import AdvancedReporter, ReportConfig


def create_test_data():
    """Create test data for reporting."""
    # Create test targets
    target1 = ScanTarget(url="https://example.com/search?q=test")
    target2 = ScanTarget(url="https://example.com/login?redirect=home")

    # Create vulnerabilities
    vuln1 = VulnerabilityResult(
        url="https://example.com/search?q=test",
        parameter="q",
        payload="<script>alert('XSS')</script>",
        response_snippet="<div>Search for: <script>alert('XSS')</script></div>",
        level=VulnerabilityLevel.HIGH,
    )

    vuln2 = VulnerabilityResult(
        url="https://example.com/search?q=test",
        parameter="q",
        payload="'><img src=x onerror=alert(1)>",
        response_snippet="<input value=''><img src=x onerror=alert(1)>'>",
        level=VulnerabilityLevel.CRITICAL,
    )

    vuln3 = VulnerabilityResult(
        url="https://example.com/login?redirect=home",
        parameter="redirect",
        payload="javascript:alert('XSS')",
        response_snippet="<a href='javascript:alert('XSS')'>Home</a>",
        level=VulnerabilityLevel.MEDIUM,
    )

    # Create scan results
    result1 = ScanResult(
        target=target1,
        vulnerabilities=[vuln1, vuln2],
        scan_duration=2.5,
        waf_detected="Cloudflare",
    )

    result2 = ScanResult(
        target=target2, vulnerabilities=[vuln3], scan_duration=1.8, waf_detected=None
    )

    return [result1, result2]


def test_html_report():
    """Test HTML report generation."""
    print("🧪 Testing HTML Report Generation...")

    # Create test data
    results = create_test_data()

    # Configure report
    config = ReportConfig(
        include_payloads=True,
        include_technical_details=True,
        include_recommendations=True,
    )

    # Generate report
    reporter = AdvancedReporter(config)

    try:
        report_path = reporter.generate_comprehensive_report(
            results, Path("/home/jarek/xss_vibes/test_report.html"), "html"
        )
        print(f"✅ HTML Report generated: {report_path}")
        return True
    except Exception as e:
        print(f"❌ HTML Report failed: {e}")
        return False


def test_json_report():
    """Test JSON report generation."""
    print("🧪 Testing JSON Report Generation...")

    # Create test data
    results = create_test_data()

    # Configure report
    config = ReportConfig(
        include_payloads=True,
        include_technical_details=False,
        include_recommendations=True,
    )

    # Generate report
    reporter = AdvancedReporter(config)

    try:
        report_path = reporter.generate_comprehensive_report(
            results, Path("/home/jarek/xss_vibes/test_report.json"), "json"
        )
        print(f"✅ JSON Report generated: {report_path}")
        return True
    except Exception as e:
        print(f"❌ JSON Report failed: {e}")
        return False


def test_csv_report():
    """Test CSV report generation."""
    print("🧪 Testing CSV Report Generation...")

    # Create test data
    results = create_test_data()

    # Configure report
    config = ReportConfig(
        include_payloads=False,  # CSV typically excludes complex data
        include_technical_details=False,
        include_recommendations=False,
    )

    # Generate report
    reporter = AdvancedReporter(config)

    try:
        report_path = reporter.generate_comprehensive_report(
            results, Path("/home/jarek/xss_vibes/test_report.csv"), "csv"
        )
        print(f"✅ CSV Report generated: {report_path}")
        return True
    except Exception as e:
        print(f"❌ CSV Report failed: {e}")
        return False


def test_markdown_report():
    """Test Markdown report generation."""
    print("🧪 Testing Markdown Report Generation...")

    # Create test data
    results = create_test_data()

    # Configure report
    config = ReportConfig(
        include_payloads=True,
        include_technical_details=True,
        include_recommendations=True,
    )

    # Generate report
    reporter = AdvancedReporter(config)

    try:
        report_path = reporter.generate_comprehensive_report(
            results, Path("/home/jarek/xss_vibes/test_report.md"), "markdown"
        )
        print(f"✅ Markdown Report generated: {report_path}")
        return True
    except Exception as e:
        print(f"❌ Markdown Report failed: {e}")
        return False


if __name__ == "__main__":
    print("🎯 Testing Advanced Reporting System\n")

    tests = [test_html_report, test_json_report, test_csv_report, test_markdown_report]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All reporting tests passed!")
    else:
        print("⚠️  Some tests failed. Check the output above.")
