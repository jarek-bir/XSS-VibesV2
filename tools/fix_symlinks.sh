#!/bin/bash
# XSS Vibes - Symlink Updater (Post-Reorganization)

echo "🔧 XSS Vibes - Updating Symlinks After Reorganization"
echo "=" * 60

XSS_VIBES_DIR="/home/jarek/xss_vibes"
LOCAL_BIN="$HOME/.local/bin"

# Create backup of old symlinks
echo "📋 Backing up old symlinks..."
mkdir -p "$HOME/.local/bin/backup_$(date +%Y%m%d)"
cp "$LOCAL_BIN"/xss-* "$HOME/.local/bin/backup_$(date +%Y%m%d)/" 2>/dev/null || echo "No old symlinks to backup"

# Remove old symlinks
echo "🗑️  Removing old symlinks..."
rm -f "$LOCAL_BIN"/xss-*

# Create new symlinks with correct paths
echo "🔗 Creating new symlinks..."

# Main XSS Vibes
cat > "$LOCAL_BIN/xss-vibes" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 -m xss_vibes "$@"
EOF

# Automation scripts (now in tools/automation/)
cat > "$LOCAL_BIN/xss-ultimate" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && bash "/home/jarek/xss_vibes/tools/automation/ultimate_tester.sh" "$@"
EOF

cat > "$LOCAL_BIN/xss-god-tier" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && bash "/home/jarek/xss_vibes/tools/automation/god_tier_tester.sh" "$@"
EOF

cat > "$LOCAL_BIN/xss-quick" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && bash "/home/jarek/xss_vibes/tools/automation/quick_multi_test.sh" "$@"
EOF

cat > "$LOCAL_BIN/xss-oneliners" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && bash "/home/jarek/xss_vibes/tools/automation/robust_oneliners.sh" "$@"
EOF

cat > "$LOCAL_BIN/xss-multi" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/tools/automation/multi_vuln_tester.py" "$@"
EOF

# Analysis scripts (now in tools/analysis/)
cat > "$LOCAL_BIN/xss-context" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/tools/analysis/ai_context_extractor.py" "$@"
EOF

cat > "$LOCAL_BIN/xss-smart" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/tools/analysis/smart_payload_selector.py" "$@"
EOF

# Core scripts (still in scripts/)
cat > "$LOCAL_BIN/xss-encoder" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/scripts/advanced_encoder.py" "$@"
EOF

cat > "$LOCAL_BIN/xss-polyglot" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/scripts/enhanced_dpe_generator.py" "$@"
EOF

cat > "$LOCAL_BIN/xss-dpe" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/scripts/enhanced_dpe_generator.py" "$@"
EOF

cat > "$LOCAL_BIN/xss-service" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/scripts/service_checker.py" "$@"
EOF

cat > "$LOCAL_BIN/xss-status" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && bash "/home/jarek/xss_vibes/scripts/project_status.sh" "$@"
EOF

# AI Tools
cat > "$LOCAL_BIN/xss-ai-domfuzz" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 -m xss_vibes.ai_domfuzz "$@"
EOF

cat > "$LOCAL_BIN/xss-report" << 'EOF'
#!/bin/bash
cd "/home/jarek/xss_vibes" && python3 "/home/jarek/xss_vibes/scripts/report_gen.py" "$@"
EOF

# Help command
cat > "$LOCAL_BIN/xss-help" << 'EOF'
#!/bin/bash
echo "🔥 XSS Vibes V2 - Available Commands (Post-Reorganization)"
echo "=" * 60
echo ""
echo "🎯 CORE TOOLS:"
echo "  xss-vibes         - Main XSS scanner"
echo "  xss-quick         - Quick multi-target test"
echo "  xss-ultimate      - Ultimate comprehensive tester"
echo "  xss-god-tier      - God-tier advanced testing"
echo ""
echo "🧠 AI-POWERED TOOLS:"
echo "  xss-context       - AI Context Extractor"
echo "  xss-ai-domfuzz    - AI DOM Fuzzer"
echo "  xss-report        - Generate HTML reports"
echo "  xss-smart         - Smart payload selector"
echo ""
echo "🔧 UTILITIES:"
echo "  xss-encoder       - Advanced payload encoder"
echo "  xss-polyglot      - Polyglot generator"
echo "  xss-dpe           - DPE (Data Processing Engine) payloads"
echo "  xss-oneliners     - Robust oneliners"
echo "  xss-multi         - Multi-vulnerability tester"
echo ""
echo "📊 STATUS & INFO:"
echo "  xss-status        - Project status check"
echo "  xss-service       - Service checker"
echo "  xss-help          - This help message"
echo ""
echo "🚀 Example Usage:"
echo "  xss-quick https://testphp.vulnweb.com"
echo "  xss-dpe list"
echo "  xss-dpe generate --category polyglot --count 10"
echo "  xss-context /path/to/file.js --format json"
echo "  xss-ai-domfuzz --input file.html --contexts react,dom"
echo ""
echo "📋 New Structure (Post-Cleanup):"
echo "  tools/analysis/    - AI Context Extractor, Smart selector"
echo "  tools/automation/  - Ultimate testers, oneliners"
echo "  tools/integration/ - Payload integration scripts"
echo "  scripts/          - Core utilities, report generator"
EOF

# Make all scripts executable
chmod +x "$LOCAL_BIN"/xss-*

echo ""
echo "✅ Symlinks updated successfully!"
echo ""
echo "📋 Available commands:"
ls -1 "$LOCAL_BIN"/xss-* | sed 's|.*/||' | sort

echo ""
echo "🧪 Testing xss-quick..."
if [ -f "$XSS_VIBES_DIR/tools/automation/quick_multi_test.sh" ]; then
    echo "✅ quick_multi_test.sh found in correct location"
else
    echo "❌ quick_multi_test.sh not found!"
    echo "Searching for it..."
    find "$XSS_VIBES_DIR" -name "quick_multi_test.sh" -type f
fi

echo ""
echo "💡 Try: xss-quick https://testphp.vulnweb.com"
echo "💡 Try: xss-dpe list"
echo "🔥 XSS Vibes V2 symlinks ready!"
