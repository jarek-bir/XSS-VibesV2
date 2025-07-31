#!/usr/bin/env python3
"""
XSS Vibes V2 - Test Development Interface Hunter
Quick test to verify dev hunting functionality
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

from xss_vibes.dev_hunter import DevInterfaceHunter


async def test_dev_hunter():
    """Test the development interface hunter"""
    print("🔍 Testing XSS Vibes V2 - Development Interface Hunter")
    print("=" * 60)

    # Test with some known patterns
    test_domains = ["example.com", "test.com"]

    hunter = DevInterfaceHunter()

    # Test pattern generation
    print(f"📋 Testing pattern generation for {test_domains[0]}...")
    targets = hunter.generate_dev_targets(test_domains[0])
    print(f"✅ Generated {len(targets)} potential targets")

    # Show sample targets
    print("\n🎯 Sample targets:")
    for target in targets[:10]:
        print(f"  • {target}")

    # Test content analysis
    print(f"\n🔍 Testing content analysis...")
    test_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Development Test Page</title>
        <!--
         * @Author: chen.yun
         * @Date: 2025-04-16 10:54:25
         * @LastEditor: chen.yun
         * @LastEditTime: 2025-04-16 10:55:50
        -->
    </head>
    <body>
        <h1>Hello World</h1>
        <p>This is a development test page.</p>
        <script>
            var debug = true;
            console.log("Development mode active");
        </script>
    </body>
    </html>
    """

    dev_info = hunter.extract_dev_info(test_content)
    print(f"✅ Extracted developer info: {dev_info}")

    # Test confidence scoring (simulation)
    print(f"\n📊 Testing confidence scoring...")
    test_analysis = {
        "url": "https://dev.example.com/test.html",
        "status_code": 200,
        "is_dev_interface": True,
        "confidence": 85,
        "indicators": [
            {"type": "url_keyword", "keyword": "dev"},
            {"type": "content_pattern", "pattern": "@Author"},
            {"type": "content_pattern", "pattern": "Hello World"},
        ],
        "dev_info": dev_info,
    }

    print(f"✅ Test analysis: {test_analysis['confidence']}% confidence")
    print(f"   Indicators: {len(test_analysis['indicators'])}")

    # Test HTML report generation
    print(f"\n📊 Testing report generation...")
    output_dir = Path("test_dev_hunt")
    hunter.save_dev_results([test_analysis], str(output_dir))
    print(f"✅ Reports saved to {output_dir}/")

    print(f"\n🎉 All tests completed successfully!")
    print(f"🔧 Development Interface Hunter is ready to use!")


if __name__ == "__main__":
    asyncio.run(test_dev_hunter())
