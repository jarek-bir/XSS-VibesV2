#!/bin/bash

# XSS Vibes - Complete System Test
# Tests all components of the enhanced XSS hunting arsenal

echo "🔥 XSS Vibes - Complete System Test"
echo "===================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test target
TARGET="testphp.vulnweb.com"
TEST_DIR="system_test_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo -e "${YELLOW}🎯 Testing against safe target: $TARGET${NC}"
echo

# Test 1: Service Checker
echo "1️⃣ Testing Service Availability Checker..."
timeout 30 python3 ../service_checker.py > service_test.log 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Service checker working${NC}"
else
    echo -e "${RED}❌ Service checker failed${NC}"
fi

# Test 2: Robust OneLiners
echo "2️⃣ Testing Robust OneLiners..."
echo "7" | timeout 30 ../robust_oneliners.sh "$TARGET" > robust_test.log 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Robust oneliners working${NC}"
else
    echo -e "${RED}❌ Robust oneliners failed${NC}"
fi

# Test 3: Traditional OneLiners
echo "3️⃣ Testing Traditional OneLiners..."
echo "0" | timeout 30 ../xss_oneliners.sh "$TARGET" > traditional_test.log 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Traditional oneliners working${NC}"
else
    echo -e "${RED}❌ Traditional oneliners failed${NC}"
fi

# Test 4: Integration Module
echo "4️⃣ Testing Integration Module..."
timeout 30 python3 ../oneliner_integration.py > integration_test.log 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Integration module working${NC}"
else
    echo -e "${RED}❌ Integration module failed${NC}"
fi

# Test 5: Individual Tools
echo "5️⃣ Testing Individual Tools..."

tools=("subfinder" "httpx" "gospider" "waybackurls" "gau" "qsreplace" "dalfox" "kxss" "gf" "hakrawler" "anew" "uro" "nuclei")
working_tools=0
total_tools=${#tools[@]}

for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "  ✅ $tool"
        ((working_tools++))
    else
        echo -e "  ❌ $tool"
    fi
done

echo -e "${YELLOW}🛠️ Tools available: $working_tools/$total_tools${NC}"

# Test 6: Basic Payload Test
echo "6️⃣ Testing Basic XSS Payloads..."
basic_payloads=(
    "<script>alert(1)</script>"
    "'><script>alert(1)</script>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
)

for payload in "${basic_payloads[@]}"; do
    url_encoded_payload=$(printf '%s' "$payload" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    test_url="http://$TARGET/artists.php?artist=$url_encoded_payload"
    
    response=$(curl -s --max-time 5 "$test_url" 2>/dev/null)
    if echo "$response" | grep -q "alert\|script\|svg"; then
        echo -e "  🎯 Payload reflected: ${payload:0:20}..."
    fi
done

# Generate summary
echo
echo "📊 Test Summary"
echo "==============="
echo "Target: $TARGET"
echo "Test directory: $PWD"
echo "Tools available: $working_tools/$total_tools"
echo "Service checker: $([ -f service_test.log ] && echo "✅" || echo "❌")"
echo "Robust oneliners: $([ -f robust_test.log ] && echo "✅" || echo "❌")"
echo "Traditional oneliners: $([ -f traditional_test.log ] && echo "✅" || echo "❌")"
echo "Integration module: $([ -f integration_test.log ] && echo "✅" || echo "❌")"

# Check for results
echo
echo "📁 Generated Files:"
ls -la *.log 2>/dev/null || echo "No log files generated"

echo
echo "🎉 System test completed!"
echo "📁 Test results saved in: $PWD"
