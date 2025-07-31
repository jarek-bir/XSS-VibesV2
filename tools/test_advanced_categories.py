#!/usr/bin/env python3
"""
XSS Vibes V2 - Advanced Categories Tester
Quick test for new XSS categories
"""

import json
import sys
from pathlib import Path


def test_category(category_name):
    """Test specific category"""
    category_file = Path(f"xss_vibes/data/categories/{category_name}.json")

    if not category_file.exists():
        print(f"❌ Category not found: {category_name}")
        return False

    with open(category_file, "r", encoding="utf-8") as f:
        category_data = json.load(f)

    print(f"\n🔥 {category_data['category'].upper()}")
    print(f"📋 {category_data['description']}")
    print(f"⚡ Difficulty: {category_data['difficulty']}")
    print(f"🎯 Payloads: {len(category_data['payloads'])}")

    # Show first 3 payloads
    print(f"\n💀 Sample Payloads:")
    for i, payload in enumerate(category_data["payloads"][:3]):
        print(f"   {i+1}. {payload['name']}")
        print(
            f"      ↳ {payload['payload'][:80]}{'...' if len(payload['payload']) > 80 else ''}"
        )
        print(f"      ↳ Evasion Level: {payload['evasion_level']}/10")
        print()

    return True


def main():
    """Test all new categories"""
    new_categories = [
        "template_injection",
        "event_handler_injection",
        "javascript_uri_injection",
        "innerhtml_svg_namespace",
        "javascript_proto_pollution_xss",
        "url_js_context",
    ]

    print("🔥 XSS Vibes V2 - Advanced Categories Test")
    print("=" * 50)

    success_count = 0
    for category in new_categories:
        if test_category(category):
            success_count += 1

    print(f"\n✅ Successfully tested {success_count}/{len(new_categories)} categories")

    if len(sys.argv) > 1:
        specific_category = sys.argv[1]
        print(f"\n🎯 Testing specific category: {specific_category}")
        test_category(specific_category)


if __name__ == "__main__":
    main()
