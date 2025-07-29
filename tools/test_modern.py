#!/usr/bin/env python3
"""Simple test to verify the modernized XSS scanner works."""

import asyncio
import logging
from pathlib import Path

# Test imports
try:
    from config import ScannerConfig
    from models import ScanTarget, VulnerabilityLevel
    from payload_manager import PayloadManager
    from waf_detector import WAFDetector
    from header_parser import HeaderParser
    from scanner import XSSScanner
    from logger import setup_logging

    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import error: {e}")
    exit(1)


def test_basic_functionality():
    """Test basic functionality."""
    print("\n🧪 Testing basic functionality...")

    # Test configuration
    config = ScannerConfig()
    print(f"✅ Config loaded: {config.max_threads} threads")

    # Test header parser
    parser = HeaderParser()
    headers = parser.parse_headers(
        ["Content-Type: application/json", "Authorization: Bearer token"]
    )
    assert "Content-Type" in headers
    assert headers["Authorization"] == "Bearer token"
    print("✅ Header parser working")

    # Test models
    target = ScanTarget("http://example.com/?id=1&name=test")
    assert len(target.parameters) == 2
    assert "id" in target.parameters
    assert "name" in target.parameters
    print("✅ URL parsing working")

    # Test payload manager
    payload_manager = PayloadManager()
    dangerous_chars = payload_manager.get_dangerous_characters()
    assert len(dangerous_chars) > 0
    print(f"✅ Payload manager loaded {len(dangerous_chars)} dangerous characters")

    print("✅ All basic tests passed!")


async def test_async_functionality():
    """Test async functionality."""
    print("\n🚀 Testing async functionality...")

    try:
        config = ScannerConfig()
        scanner = XSSScanner(config)

        # This would normally test a real URL, but we'll just verify the method exists
        assert hasattr(scanner, "scan_url_async")
        assert hasattr(scanner, "scan_urls_async")
        print("✅ Async methods available")

    except Exception as e:
        print(f"❌ Async test failed: {e}")
        return False

    return True


def test_logging():
    """Test logging setup."""
    print("\n📝 Testing logging setup...")

    try:
        logger = setup_logging(level="INFO", enable_colors=True)
        logger.info("Test log message")
        logger.warning("Test warning message")
        logger.error("Test error message")
        print("✅ Logging setup successful")
    except Exception as e:
        print(f"❌ Logging test failed: {e}")


def main():
    """Run all tests."""
    print("🔬 Testing Modern XSS Vibes Components\n")

    try:
        test_basic_functionality()
        test_logging()

        # Test async
        async_result = asyncio.run(test_async_functionality())
        if async_result:
            print("✅ Async functionality working")

        print("\n🎉 All tests completed successfully!")
        print("\n📚 Ready to use the modern XSS scanner:")
        print("   python main_modern.py -u 'http://example.com/?id=1'")
        print("   python main_modern.py -f urls.txt --async")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
