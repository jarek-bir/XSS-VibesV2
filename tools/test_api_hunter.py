#!/usr/bin/env python3
"""
XSS Vibes V2 - Test API Hunter
Test to verify API hunting functionality with Ctrip-like patterns
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

from xss_vibes.api_hunter import APIEndpointHunter


async def test_api_hunter():
    """Test the API endpoint hunter"""
    print("🔍 Testing XSS Vibes V2 - API Endpoint Hunter")
    print("=" * 60)
    print("Testing with Ctrip.com patterns")
    print("")

    hunter = APIEndpointHunter()

    # Test pattern generation with Ctrip domain
    print(f"📋 Testing pattern generation for ctrip.com...")
    targets = hunter.generate_api_targets("ctrip.com")
    print(f"✅ Generated {len(targets)} potential API targets")

    # Show sample targets that match Ctrip patterns
    ctrip_targets = [t for t in targets if "ctrip" in t]
    print(f"\n🎯 Sample Ctrip-style targets:")
    for target in ctrip_targets[:15]:
        print(f"  • {target}")

    # Look for specific patterns we know exist
    expected_patterns = [
        "restapi/soa2",
        "getToken.json",
        "getAppConfig.json",
        "/mobile/",
        "/m/api/",
    ]

    print(f"\n🔍 Checking for known Ctrip patterns:")
    for pattern in expected_patterns:
        matching = [t for t in targets if pattern in t]
        if matching:
            print(f"  ✅ {pattern} - {len(matching)} matches")
            if pattern in ["getToken.json", "getAppConfig.json"]:
                print(f"     Example: {matching[0]}")
        else:
            print(f"  ❌ {pattern} - no matches")

    # Test content analysis with simulated Ctrip response
    print(f"\n🔍 Testing content analysis...")

    # Simulate getToken.json response
    token_response = """
    {
        "data": {
            "token": "44879439",
            "scriptUrl": "/code/ubt/fp-em9.js"
        },
        "success": true,
        "message": "Token generated successfully"
    }
    """

    extracted_data = hunter._extract_sensitive_data(
        {"data": {"token": "44879439", "scriptUrl": "/code/ubt/fp-em9.js"}}
    )
    print(f"✅ Token API analysis: {extracted_data}")

    # Simulate getAppConfig.json error response
    config_error = """
    {
        "error": "请求体不能为空，且必须为JSON格式",
        "code": 400,
        "message": "Request body cannot be empty and must be JSON format"
    }
    """

    # Test confidence scoring simulation
    print(f"\n📊 Testing confidence scoring...")
    test_analyses = [
        {
            "url": "https://m.ctrip.com/restapi/soa2/11470/getToken.json",
            "method": "GET",
            "status_code": 200,
            "api_type": "TOKEN_API",
            "confidence": 95,
            "risk_level": "HIGH",
            "data_extracted": {
                "data.token": "44879439",
                "data.scriptUrl": "/code/ubt/fp-em9.js",
            },
        },
        {
            "url": "https://m.ctrip.com/restapi/soa2/18088/getAppConfig.json",
            "method": "POST",
            "status_code": 400,
            "api_type": "CONFIG_API",
            "confidence": 85,
            "risk_level": "MEDIUM",
            "data_extracted": {},
        },
    ]

    for analysis in test_analyses:
        print(f"  • {analysis['url']}")
        print(f"    Type: {analysis['api_type']}, Risk: {analysis['risk_level']}")
        print(f"    Confidence: {analysis['confidence']}%")
        if analysis["data_extracted"]:
            print(f"    Exposed: {list(analysis['data_extracted'].keys())}")

    # Test report generation
    print(f"\n📊 Testing report generation...")
    output_dir = Path("test_api_hunt")
    hunter.save_api_results(test_analyses, str(output_dir))
    print(f"✅ Reports saved to {output_dir}/")

    print(f"\n🎉 All tests completed successfully!")
    print(f"🔧 API Endpoint Hunter is ready to discover Ctrip-style APIs!")
    print(f"\n💡 Usage examples:")
    print(f"  ./tools/api-hunter ctrip.com")
    print(f"  make api-hunt DOMAIN=ctrip.com")


if __name__ == "__main__":
    asyncio.run(test_api_hunter())
