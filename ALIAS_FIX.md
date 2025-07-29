# 🔧 XSS Vibes - Alias Conflict Fix

## Problem
If you get errors like:
```bash
xss-ultimate
zsh: no such file or directory: /home/jarek/xss_vibes/ultimate_tester.sh
```

This happens because old aliases are conflicting with new symlinks.

## Quick Fix 🚀

Run these commands in your terminal:

```bash
# 1. Remove old XSS aliases
unalias xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help 2>/dev/null

# 2. Clear shell hash table
hash -d xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help 2>/dev/null

# 3. Reload shell or run
exec $SHELL

# 4. Test commands
xss-help
xss-ultimate -t testphp.vulnweb.com -m quick
```

## Permanent Fix 🔒

To prevent this in the future, add this to your `~/.zshrc` or `~/.bashrc`:

```bash
# XSS Vibes - Prevent alias conflicts
unalias xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help 2>/dev/null
```

## Verification ✅

After fix, verify commands work:
```bash
which xss-ultimate
# Should show: /home/jarek/.local/bin/xss-ultimate

xss-help
# Should show: XSS Vibes Advanced Commands menu

xss-vibes --help  
# Should show: XSS Vibes main scanner help
```

## Why This Happens 🤔

1. **Old Setup**: Previously XSS commands were set as shell aliases
2. **New Setup**: Now they're symlinks in `~/.local/bin`
3. **Priority**: Shell aliases have higher priority than PATH binaries
4. **Solution**: Remove aliases to let symlinks work

## Global Commands Available 🎯

After fix, these commands work globally:
- `xss-vibes` - Main XSS scanner
- `xss-ultimate` - Complete vulnerability assessment  
- `xss-god-tier` - GOD TIER payload testing
- `xss-smart` - Intelligent payload selection
- `xss-encoder` - Advanced payload encoding
- `xss-service` - Service availability check
- `xss-multi` - Multi-vulnerability scanner
- `xss-quick` - Quick multi-vuln test
- `xss-status` - Project status report
- `xss-oneliners` - Robust hunting with fallbacks
- `xss-help` - Show all commands

## Support 💬

If issues persist:

1. **Check PATH**: `echo $PATH | grep .local/bin`
2. **Verify symlinks**: `ls -la ~/.local/bin/xss-*`
3. **Re-run setup**: `./scripts/setup_aliases.sh`
4. **Install package**: `pip3 install -e .` (from main directory)
5. **Check installation**: `xss-vibes --version`

### Installation Issues 🔧

If `pip3 install -e .` fails with "not a Python project":

```bash
# Make sure you're in the main directory (not xss_vibes/xss_vibes)
cd /home/jarek/xss_vibes

# Ensure setup.py exists in root
ls setup.py

# If missing, copy from scripts
cp scripts/setup.py .

# Then install
pip3 install -e .
```

### Fresh Installation 🆕

For completely fresh setup:

```bash
cd /home/jarek/xss_vibes
pip3 install -e .                    # Install package
./scripts/setup_aliases.sh           # Setup global commands
xss-help                             # Verify commands work
```
