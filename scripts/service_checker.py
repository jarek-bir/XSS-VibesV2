#!/usr/bin/env python3
"""
XSS Vibes - Service Availability Checker
Checks if external APIs and services are working before running hunting techniques
"""
import requests
import subprocess
import time
import json
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError


class ServiceChecker:
    """Check availability of external services and APIs"""

    def __init__(self):
        self.timeout = 10
        self.services = {
            # Web archive services
            "wayback_machine": "https://web.archive.org",
            # Security services
            "crt_sh": "https://crt.sh",
            "urlscan_io": "https://urlscan.io/api/v1/search/",
            # Bug bounty platforms
            "hackerone": "https://hackerone.com",
            "bugcrowd": "https://bugcrowd.com",
            # Subdomain enumeration
            "chaos_api": "https://chaos.projectdiscovery.io",
            "recon_dev": "https://recon.dev",
            # XSS Hunter services
            "xss_hunter": "https://xsshunter.com",
            "ezxss": "https://ezxss.com",
            # Alternative archives
            "arquivo_pt": "https://arquivo.pt",
            "archive_today": "https://archive.today",
        }

        self.tool_endpoints = {
            # Services that tools depend on
            "waybackurls": ["https://web.archive.org/cdx/search/cdx"],
            "gau": ["https://web.archive.org"],
            "hakrawler": ["https://web.archive.org"],
            "subfinder": ["https://crt.sh", "https://api.hackertarget.com"],
            "amass": ["https://crt.sh", "https://api.hackertarget.com"],
        }

    def check_service(self, name: str, url: str) -> Tuple[str, bool, str]:
        """Check if a single service is available"""
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 200:
                return (name, True, f"✅ {name}: Online ({response.status_code})")
            else:
                return (name, False, f"⚠️ {name}: HTTP {response.status_code}")
        except requests.exceptions.Timeout:
            return (name, False, f"🕒 {name}: Timeout ({self.timeout}s)")
        except requests.exceptions.ConnectionError:
            return (name, False, f"❌ {name}: Connection failed")
        except Exception as e:
            return (name, False, f"💥 {name}: {str(e)[:50]}")

    def check_all_services(self) -> Dict[str, bool]:
        """Check all services in parallel"""
        print("🔍 Checking external service availability...")
        print("=" * 60)

        results = {}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.check_service, name, url): name
                for name, url in self.services.items()
            }

            for future in futures:
                try:
                    name, status, message = future.result(timeout=15)
                    results[name] = status
                    print(message)
                except TimeoutError:
                    name = futures[future]
                    results[name] = False
                    print(f"⏰ {name}: Check timed out")
                except Exception as e:
                    name = futures[future]
                    results[name] = False
                    print(f"💥 {name}: Check failed - {e}")

        print()
        return results

    def check_tool_dependencies(self, tool_name: str) -> bool:
        """Check if a tool's dependencies are available"""
        if tool_name not in self.tool_endpoints:
            return True  # Unknown tool, assume OK

        endpoints = self.tool_endpoints[tool_name]
        available_count = 0

        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 200:
                    available_count += 1
            except:
                pass

        # Return True if at least one endpoint is available
        return available_count > 0

    def get_wayback_alternatives(self) -> List[str]:
        """Get alternative wayback machine endpoints"""
        alternatives = [
            "https://web.archive.org/cdx/search/cdx",
            "https://arquivo.pt/wayback",
            "https://archive.today",
        ]

        working_alternatives = []
        for alt in alternatives:
            try:
                response = requests.get(alt, timeout=5)
                if response.status_code == 200:
                    working_alternatives.append(alt)
            except:
                pass

        return working_alternatives

    def create_fallback_config(self) -> Dict:
        """Create configuration with fallbacks for failed services"""
        service_status = self.check_all_services()

        config = {"services": service_status, "fallbacks": {}, "recommendations": []}

        # Wayback fallbacks
        if not service_status.get("wayback_machine", False):
            wayback_alts = self.get_wayback_alternatives()
            config["fallbacks"]["wayback"] = wayback_alts
            if wayback_alts:
                config["recommendations"].append(
                    f"Wayback Machine down - using alternatives: {', '.join(wayback_alts)}"
                )
            else:
                config["recommendations"].append(
                    "All Wayback services down - consider local URL lists"
                )

        # Subdomain enumeration fallbacks
        if not service_status.get("crt_sh", False):
            config["recommendations"].append(
                "crt.sh down - use: subfinder with different sources, amass passive mode"
            )

        # XSS Hunter fallbacks
        if not service_status.get("xss_hunter", False):
            config["recommendations"].append(
                "XSS Hunter down - use: local Burp Collaborator, ngrok tunnels, or ezXSS"
            )

        return config

    def generate_offline_techniques(self) -> List[str]:
        """Generate XSS hunting techniques that work offline"""
        techniques = [
            # Local file analysis
            "find . -name '*.js' -exec grep -l 'innerHTML\\|outerHTML\\|eval\\|setTimeout' {} \\;",
            # Local endpoint discovery
            "grep -r 'api\\|endpoint\\|url' . --include='*.js' --include='*.html'",
            # Parameter extraction from local files
            "grep -oE '\\?[a-zA-Z0-9_]+(=[^&]*)?(&[a-zA-Z0-9_]+(=[^&]*)?)*' . -r",
            # Form analysis
            "grep -r '<form' . --include='*.html' --include='*.php'",
            # Local payload testing
            "curl -s 'http://localhost/test?param=<script>alert(1)</script>'",
            # Manual wordlist generation
            "cat /usr/share/wordlists/dirb/common.txt | sed 's/$/=test/' > local_params.txt",
        ]

        return techniques

    def save_status_report(self, filename: str = "service_status.json"):
        """Save service status to file"""
        status = self.check_all_services()
        config = self.create_fallback_config()

        report = {
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "services": status,
            "config": config,
            "offline_techniques": self.generate_offline_techniques(),
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        print(f"📊 Status report saved to: {filename}")
        return report


def create_robust_oneliners():
    """Create oneliners with fallbacks for service failures"""

    robust_commands = {
        "wayback_with_fallbacks": """
# Wayback with multiple fallbacks
waybackurls {target} 2>/dev/null || \\
curl -s "https://arquivo.pt/wayback/cdx?url={target}/*" 2>/dev/null || \\
echo "Using local URL list..." && cat saved_urls.txt 2>/dev/null || \\
echo "All wayback services failed - using manual discovery"
""",
        "subdomain_enum_robust": """
# Robust subdomain enumeration
subfinder -d {target} -silent 2>/dev/null || \\
amass enum -passive -d {target} 2>/dev/null || \\
(echo "API services down - using DNS bruteforce:" && \\
 for sub in www api admin test dev staging; do \\
   dig +short $sub.{target} | head -1; \\
 done)
""",
        "gau_with_fallbacks": """
# GAU with fallbacks
gau {target} 2>/dev/null || \\
waybackurls {target} 2>/dev/null || \\
echo "Using manual URL discovery..."
""",
        "xss_test_offline": """
# XSS testing without external dependencies
echo {target} | httpx -silent | while read url; do \\
  for payload in "<script>alert(1)</script>" "javascript:alert(1)" "'><svg onload=alert(1)>"; do \\
    curl -s "$url?test=$payload" | grep -q "alert(1)" && echo "XSS found: $url"; \\
  done; \\
done
""",
        "local_js_analysis": """
# Local JavaScript analysis for XSS
find . -name "*.js" -exec grep -l "innerHTML\\|outerHTML\\|eval" {} \\; | \\
while read file; do \\
  echo "Analyzing: $file"; \\
  grep -n "innerHTML\\|outerHTML\\|eval" "$file"; \\
done
""",
    }

    return robust_commands


def main():
    """Main function"""
    print("🔥 XSS Vibes - Service Availability Checker")
    print("=" * 60)

    checker = ServiceChecker()

    # Check all services
    status_report = checker.save_status_report()

    # Print summary
    working_services = sum(1 for status in status_report["services"].values() if status)
    total_services = len(status_report["services"])

    print(f"\n📊 Service Summary:")
    print(f"✅ Working: {working_services}/{total_services}")
    print(f"❌ Failed: {total_services - working_services}/{total_services}")

    # Print recommendations
    if status_report["config"]["recommendations"]:
        print(f"\n💡 Recommendations:")
        for rec in status_report["config"]["recommendations"]:
            print(f"  • {rec}")

    # Generate robust oneliners
    print(f"\n🛠️ Generating robust oneliners...")
    robust_commands = create_robust_oneliners()

    with open("robust_oneliners.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# XSS Vibes - Robust OneLiners with Fallbacks\n")
        f.write("# Generated with service availability check\n\n")

        for name, command in robust_commands.items():
            f.write(f"# {name.replace('_', ' ').title()}\n")
            f.write(f"{command}\n\n")

    print("✅ Robust oneliners saved to: robust_oneliners.sh")

    # Create offline hunting guide
    if working_services < total_services * 0.5:  # If more than 50% services are down
        print("\n⚠️ Many services are down. Creating offline hunting guide...")

        offline_guide = """# XSS Vibes - Offline Hunting Guide

## When External APIs Are Down

### 1. Local File Analysis
```bash
# Find potential XSS in JavaScript files
find . -name "*.js" -exec grep -l "innerHTML|outerHTML|eval|setTimeout" {} \\;

# Extract parameters from local files  
grep -oE '\\?[a-zA-Z0-9_]+(=[^&]*)?(&[a-zA-Z0-9_]+(=[^&]*)?)*' . -r

# Find forms that might be vulnerable
grep -r '<form' . --include='*.html' --include='*.php'
```

### 2. Manual Parameter Discovery
```bash
# Common parameter wordlist
echo -e "q\\nsearch\\nquery\\ninput\\ndata\\nvalue\\nname\\nuser\\nid" > params.txt

# Test each parameter
while read param; do
  curl -s "http://target.com/page?$param=<script>alert(1)</script>"
done < params.txt
```

### 3. Local Testing Environment
```bash
# Setup local test server
python3 -m http.server 8000

# Test payloads locally
curl "http://localhost:8000/test.php?param=<svg onload=alert(1)>"
```

### 4. Manual Techniques
- Browser developer tools network tab
- Manual form submission testing
- Source code review
- Burp Suite proxy (offline mode)
"""

        with open("offline_hunting_guide.md", "w") as f:
            f.write(offline_guide)

        print("📖 Offline hunting guide saved to: offline_hunting_guide.md")


if __name__ == "__main__":
    main()
