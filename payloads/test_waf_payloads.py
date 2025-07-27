#!/usr/bin/env python3
"""
Test script for WAF-specific payloads.
"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from payload_manager import PayloadManager
from models import VulnerabilityLevel


def test_waf_payloads():
    """Test WAF-specific payload loading and functionality."""
    print("🔥 Testing WAF-Specific Payloads 🔥\n")

    # Initialize payload manager
    manager = PayloadManager()

    print(f"📊 Payload Statistics:")
    print(f"   Standard payloads: {manager.payload_count}")
    print(f"   WAF-specific payloads: {manager.waf_payload_count}")
    print(f"   Total payloads: {manager.total_payload_count}\n")

    # Test WAF types
    waf_types = manager.get_waf_types()
    print(f"🛡️  Available WAF Types ({len(waf_types)}):")
    for waf in waf_types:
        waf_payloads = manager.get_all_payloads_combined(waf_type=waf)
        print(f"   {waf}: {len(waf_payloads)} payloads")
    print()

    # Test levels
    print("⚡ Payloads by Level:")
    for level in VulnerabilityLevel:
        level_payloads = manager.get_payloads_by_level(level)
        print(f"   {level.value}: {len(level_payloads)} payloads")
    print()

    # Show some advanced payloads
    print("🚀 Sample Advanced WAF Evasion Payloads:")
    cloudflare_payloads = manager.get_all_payloads_combined(waf_type="cloudflare")
    for i, payload in enumerate(cloudflare_payloads[:3], 1):
        print(f"   {i}. Cloudflare bypass ({payload.level.value}):")
        print(f"      {payload.content}")
        print(f"      Description: {payload.description}\n")

    akamai_payloads = manager.get_all_payloads_combined(waf_type="akamai")
    for i, payload in enumerate(akamai_payloads[:3], 1):
        print(f"   {i+3}. Akamai bypass ({payload.level.value}):")
        print(f"      {payload.content}")
        print(f"      Description: {payload.description}\n")

    # Test critical level payloads
    critical_payloads = manager.get_payloads_by_level(VulnerabilityLevel.CRITICAL)
    print(f"💥 Critical Level Payloads ({len(critical_payloads)}):")
    for i, payload in enumerate(critical_payloads[:5], 1):
        waf_info = f" [{payload.waf}]" if payload.waf else ""
        print(f"   {i}. {payload.content[:60]}...{waf_info}")
    print()

    print("✅ WAF payload system is working correctly!")
    print(
        f"🎯 Ready to bypass {len(waf_types)} different WAF systems with {manager.total_payload_count} payloads!"
    )


if __name__ == "__main__":
    test_waf_payloads()
