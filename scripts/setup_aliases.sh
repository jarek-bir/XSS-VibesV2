#!/bin/bash

# XSS Vibes - Setup Global Commands via Symlinks
# Creates symlinks in ~/.local/bin for global access without sourcing

echo "🔥 Setting up XSS Vibes Global Commands"
echo "======================================="

# First, remove any conflicting aliases
echo "🧹 Removing conflicting aliases..."
unalias xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help xss-vibes 2>/dev/null || true

# Clear shell hash table
hash -r 2>/dev/null || true

# Remove conflicting aliases for new commands too
unalias xss-context xss-polyglot xss-ultimate-gen 2>/dev/null || true

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

# Main XSS Vibes command
cat > "$LOCAL_BIN/xss-vibes" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 -m xss_vibes "\$@"
EOF

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

cat > "$LOCAL_BIN/xss-context" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/contextual_generator.py" "\$@"
EOF

cat > "$LOCAL_BIN/xss-multi" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/multi_vuln_tester.py" "\$@"
EOF

# Create wrapper scripts for bash scripts (better compatibility)
cat > "$LOCAL_BIN/xss-ultimate" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/ultimate_tester.sh" "\$@"
EOF

cat > "$LOCAL_BIN/xss-god-tier" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/god_tier_tester.sh" "\$@"
EOF

cat > "$LOCAL_BIN/xss-quick" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/quick_multi_test.sh" "\$@"
EOF

cat > "$LOCAL_BIN/xss-polyglot" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/hackvault_polyglot_tester.sh" "\$@"
EOF

cat > "$LOCAL_BIN/xss-status" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/project_status.sh" "\$@"
EOF

cat > "$LOCAL_BIN/xss-ultimate-gen" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && python3 "$SCRIPTS_DIR/ultimate_generator.py" "\$@"
EOF

cat > "$LOCAL_BIN/xss-oneliners" << EOF
#!/bin/bash
cd "$XSS_VIBES_DIR" && bash "$SCRIPTS_DIR/robust_oneliners.sh" "\$@"
EOF

# Create help command
cat > "$LOCAL_BIN/xss-help" << 'EOF'
#!/bin/bash
echo "🔥 XSS Vibes Advanced Commands (Global Access):"
echo "=============================================="
echo ""
echo "🎯 Main Scanner:"
echo "  xss-vibes         - Original XSS Vibes scanner (full features)"
echo ""
echo "🎯 Context-Aware Tools:"
echo "  xss-context       - Contextual payload generator"
echo "  xss-polyglot      - HackVault ultimate polyglot tester"
echo "  xss-ultimate-gen  - Ultimate payload generator (all techniques)"
echo "  xss-multi         - Multi-vulnerability scanner"
echo "🎯 Core Testing Tools:"
echo "  xss-ultimate      - Complete vulnerability assessment"
echo "  xss-god-tier      - GOD TIER payload testing"
echo "  xss-smart         - Intelligent payload selection"
echo "  xss-quick         - Quick multi-vuln test"
echo ""
echo "🔧 Utility Tools:"
echo "  xss-encoder       - Advanced payload encoding"
echo "  xss-service       - Service availability check"
echo "  xss-status        - Project status report"
echo "  xss-oneliners     - Robust hunting with fallbacks"
echo ""
echo "📖 Usage Examples:"
echo "  xss-vibes --help                               - Full scanner help"
echo "  xss-vibes scan -u target.com                   - Basic XSS scan"
echo "  xss-ultimate -t target.com -w cloudflare -m god_tier"
echo "  xss-smart target.com"
echo "  xss-context --context login_form --field username"
echo "  xss-polyglot                                   - Test HackVault polyglot"
echo "  xss-encoder '<script>alert(1)</script>' cloudflare"
echo "  xss-service"
echo ""
echo "💡 Full XSS Vibes help: xss-vibes --help"
EOF

# Make all wrapper scripts executable
chmod +x "$LOCAL_BIN"/xss-*

echo "✅ Created global commands:"
ls -la "$LOCAL_BIN"/xss-* | while read line; do echo "  🔗 $line"; done

# Fix permissions for tools that need it
echo "🔧 Fixing permissions..."
chmod +x "$SCRIPTS_DIR"/*.py 2>/dev/null || true
chmod +x "$SCRIPTS_DIR"/*.sh 2>/dev/null || true
chmod +x "$XSS_VIBES_DIR/tools"/*.py 2>/dev/null || true

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

# Add permanent alias prevention to shell config
echo "🛡️ Adding permanent alias conflict prevention..."
ANTI_ALIAS_LINE='unalias xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help xss-vibes xss-context xss-polyglot xss-ultimate-gen 2>/dev/null || true'

if [ -f ~/.zshrc ]; then
    if ! grep -q "unalias xss-ultimate" ~/.zshrc; then
        echo "# XSS Vibes - Prevent alias conflicts" >> ~/.zshrc
        echo "$ANTI_ALIAS_LINE" >> ~/.zshrc
        echo "✅ Added alias conflict prevention to ~/.zshrc"
    else
        echo "✅ Alias conflict prevention already in ~/.zshrc"
    fi
fi

if [ -f ~/.bashrc ]; then
    if ! grep -q "unalias xss-ultimate" ~/.bashrc; then
        echo "# XSS Vibes - Prevent alias conflicts" >> ~/.bashrc
        echo "$ANTI_ALIAS_LINE" >> ~/.bashrc
        echo "✅ Added alias conflict prevention to ~/.bashrc"
    else
        echo "✅ Alias conflict prevention already in ~/.bashrc"
    fi
fi

echo ""
echo "� Setup complete! Commands available immediately:"
echo ""
echo "🔥 Global XSS Vibes Commands:"
echo "   xss-help          - Show all commands"
echo "   xss-ultimate -t target.com"
echo "   xss-smart target.com"
echo "   xss-context --context login_form"
echo "   xss-polyglot      - HackVault ultimate polyglot"
echo "   xss-god-tier"
echo "   xss-encoder '<script>alert(1)</script>' cloudflare"
echo "   xss-service"
echo ""
echo "💡 Original XSS Vibes still available: xss-vibes --help"
echo "🎯 No need to restart terminal or source files!"
