#!/bin/bash

# XSS Vibes - Setup Global Commands via Symlinks
# Creates symlinks in ~/.local/bin for global access without sourcing

echo "🔥 Setting up XSS Vibes Global Commands"
echo "======================================="

# XSS Vibes directory  
XSS_VIBES_DIR="/home/jarek/xss_vibes"
SCRIPTS_DIR="$XSS_VIBES_DIR/scripts"

# Local bin directory (usually in PATH by default)
LOCAL_BIN="$HOME/.local/bin"

# Create local bin directory if it doesn't exist
mkdir -p "$LOCAL_BIN"

echo "🔧 Creating command symlinks in $LOCAL_BIN..."

# Remove existing symlinks if they exist
rm -f "$LOCAL_BIN"/xss-*

# Create wrapper scripts for Python tools (better than direct symlinks)
cat > "$LOCAL_BIN/xss-smart" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/smart_payload_selector.py" "\$@"
EOF

cat > "$LOCAL_BIN/xss-encoder" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/advanced_encoder.py" "\$@"
EOF

cat > "$LOCAL_BIN/xss-service" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/service_checker.py" "\$@"
EOF

cat > "$LOCAL_BIN/xss-multi" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/multi_vuln_tester.py" "\$@"
EOF

# Create symlinks for bash scripts  
ln -sf "$SCRIPTS_DIR/ultimate_tester.sh" "$LOCAL_BIN/xss-ultimate"
ln -sf "$SCRIPTS_DIR/god_tier_tester.sh" "$LOCAL_BIN/xss-god-tier"
ln -sf "$SCRIPTS_DIR/quick_multi_test.sh" "$LOCAL_BIN/xss-quick"
ln -sf "$SCRIPTS_DIR/project_status.sh" "$LOCAL_BIN/xss-status"
ln -sf "$SCRIPTS_DIR/robust_oneliners.sh" "$LOCAL_BIN/xss-oneliners"

# Create help command
cat > "$LOCAL_BIN/xss-help" << 'EOF'
#!/bin/bash
echo "🔥 XSS Vibes Advanced Commands (Global Access):"
echo "=============================================="
echo ""
echo "🎯 Core Testing Tools:"
echo "  xss-ultimate      - Complete vulnerability assessment"
echo "  xss-god-tier      - GOD TIER payload testing"
echo "  xss-smart         - Intelligent payload selection"
echo "  xss-multi         - Multi-vulnerability scanner"
echo "  xss-quick         - Quick multi-vuln test"
echo ""
echo "🔧 Utility Tools:"
echo "  xss-encoder       - Advanced payload encoding"
echo "  xss-service       - Service availability check"
echo "  xss-status        - Project status report"
echo "  xss-oneliners     - Robust hunting with fallbacks"
echo ""
echo "📖 Usage Examples:"
echo "  xss-ultimate -t target.com -w cloudflare -m god_tier"
echo "  xss-smart target.com"
echo "  xss-encoder '<script>alert(1)</script>' cloudflare"
echo "  xss-service"
echo ""
echo "💡 Original XSS Vibes: xss-vibes --help"
EOF

# Make all wrapper scripts executable
chmod +x "$LOCAL_BIN"/xss-*

echo "✅ Created global commands:"
ls -la "$LOCAL_BIN"/xss-* | while read line; do echo "  🔗 $line"; done

# Fix permissions for tools that need it
echo "🔧 Fixing permissions..."
chmod +x "$XSS_VIBES_DIR/multi_vuln_tester.py"
chmod +x "$XSS_VIBES_DIR/quick_multi_test.sh"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
    echo "✅ ~/.local/bin is already in your PATH"
else
    echo "⚠️ ~/.local/bin is NOT in your PATH"
    echo "📋 Add this line to your ~/.zshrc:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "🔧 Or run this command now:"
    echo "   echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
fi

echo ""
echo "� Setup complete! Commands available immediately:"
echo ""
echo "🔥 Global XSS Vibes Commands:"
echo "   xss-help          - Show all commands"
echo "   xss-ultimate -t target.com"
echo "   xss-smart target.com"
echo "   xss-god-tier"
echo "   xss-encoder '<script>alert(1)</script>' cloudflare"
echo "   xss-service"
echo ""
echo "💡 Original XSS Vibes still available: xss-vibes --help"
echo "🎯 No need to restart terminal or source files!"
