# 🔥 XSS Vibes - Ultimate Multi-Vulnerability Testing Platform

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/your-repo/xss-vibes)
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

**XSS Vibes** has evolved from a basic XSS scanner into a comprehensive multi-vulnerability testing platform with advanced evasion capabilities, GOD TIER payloads, and intelligent target analysis.

## 🎯 Features

### 🔥 Core Capabilities
- **Multi-Vulnerability Testing**: XSS, SQLi, CORS, SSRF, LFI, Open Redirect, Subdomain Takeover
- **GOD TIER Payloads**: Advanced evasion techniques including Cuneiform XSS, Unicode zero-width characters
- **Smart WAF Detection**: Automatic detection and bypass for Cloudflare, Akamai, AWS, Imperva, and more
- **Intelligent Payload Selection**: Target-specific payload recommendations based on technology stack
- **Service Monitoring**: Real-time availability checking for external APIs with automatic fallbacks

### 🛡️ Advanced Evasion Techniques
- **Cuneiform XSS**: `𒀀='',𒉺=!𒀀+𒀀` - Ancient script bypasses modern WAFs
- **Unicode Zero-Width**: `ale‌rt(1)` - Invisible characters evade detection
- **Constructor Chain**: `constructor[constructor](alert(1))()` - Advanced JavaScript execution
- **SVG Vectors**: Complex SVG-based injection techniques
- **PDF XSS**: File-based execution vectors
- **DOM Clobbering**: Advanced DOM manipulation techniques

### 🧪 Testing Modes
- **Quick Test**: Rapid vulnerability assessment
- **Comprehensive**: Full multi-vulnerability scan
- **GOD TIER**: Maximum evasion payload testing

## 🚀 Installation

### Prerequisites
```bash
# Install required tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/Emoe/kxss@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### Install XSS Vibes
```bash
git clone https://github.com/your-repo/xss-vibes.git
cd xss-vibes
pip install -r requirements.txt
python setup.py install
```

## 📖 Usage

### 🎯 Smart Payload Selection
Automatically analyzes target and selects optimal payloads:
```bash
python3 smart_payload_selector.py testphp.vulnweb.com
```

### 🔥 GOD TIER Testing
Test advanced evasion payloads:
```bash
./god_tier_tester.sh
```

### 🧪 Multi-Vulnerability Scanner
Comprehensive vulnerability testing:
```bash
python3 multi_vuln_tester.py -t example.com
```

### ⚡ Ultimate Testing Suite
Complete vulnerability assessment:
```bash
./ultimate_tester.sh -t testphp.vulnweb.com -w cloudflare -m god_tier
```

### 🔍 Service Monitoring
Check external service availability:
```bash
python3 service_checker.py
```

### 🧬 Advanced Encoding
Generate encoded payload variants:
```bash
python3 advanced_encoder.py "<script>alert(1)</script>" cloudflare
```

### 📊 Quick Multi-Test
Rapid multi-vulnerability testing:
```bash
./quick_multi_test.sh example.com
```

## 🛡️ WAF Bypass Techniques

### Supported WAF Types
- **Cloudflare**: Unicode techniques, zero-width characters
- **Akamai**: Hex encoding, CSS injection
- **AWS WAF**: JSON encoding, mixed case
- **Imperva**: Unicode encoding, PHP serialization
- **Sucuri**: Basic evasion techniques
- **F5 Big-IP**: Advanced encoding combinations
- **ModSecurity**: Pattern obfuscation

### Example WAF Bypasses
```javascript
// Cloudflare Bypass
𒀀="",𒉺=!𒀀+𒀀

// Akamai Bypass
\x3cscript\x3ealert(1)\x3c/script\x3e

// AWS WAF Bypass
"<script>alert(1)</script>"

// Imperva Bypass
\u003cscript\u003ealert(1)\u003c/script\u003e
```

## 🎯 Vulnerability Categories

### 🚨 Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS  
- DOM-based XSS
- Blind XSS
- mXSS (Mutation XSS)

### 💉 SQL Injection
- Union-based SQLi
- Boolean-based blind SQLi
- Time-based blind SQLi
- Error-based SQLi

### 🌐 CORS Misconfiguration
- Origin reflection
- Null origin bypass
- Subdomain wildcard abuse

### 🔗 Server-Side Request Forgery (SSRF)
- Internal network access
- Cloud metadata exploitation
- Protocol confusion

### 📁 Local File Inclusion (LFI)
- Path traversal
- Wrapper exploitation
- Log poisoning

### ↗️ Open Redirect
- Header injection
- JavaScript redirect
- Meta refresh redirect

## 🔧 Advanced Features

### 🧠 Intelligent Target Analysis
Automatically detects:
- Technology stack (PHP, ASP.NET, Node.js, Python)
- CMS platforms (WordPress, Drupal, Joomla)
- JavaScript frameworks (React, Angular, Vue.js)
- WAF presence and type
- Server information

### 📊 Comprehensive Reporting
- JSON output for automation
- HTML reports with charts
- CSV export for analysis
- Real-time progress tracking

### 🔄 Fallback Systems
- Automatic service failure detection
- Alternative data sources
- Offline capability maintenance
- Graceful degradation

## 📁 Project Structure

```
xss_vibes/
├── xss_vibes/                 # Core package
│   ├── scanner.py            # Main scanner engine
│   ├── payload_manager.py    # Payload management
│   ├── waf_detector.py       # WAF detection
│   ├── encoding_engine.py    # Payload encoding
│   └── data/                 # Payload databases
├── service_checker.py        # Service monitoring
├── smart_payload_selector.py # Intelligent selection
├── advanced_encoder.py       # Advanced encoding
├── multi_vuln_tester.py      # Multi-vuln scanner
├── ultimate_tester.sh        # Complete test suite
├── god_tier_tester.sh        # GOD TIER testing
└── quick_multi_test.sh       # Rapid testing
```

## 🎓 Advanced Usage Examples

### Target-Specific Testing
```bash
# Test WordPress site with Cloudflare WAF
./ultimate_tester.sh -t wordpress-site.com -w cloudflare -m comprehensive

# Quick test for React application
python3 smart_payload_selector.py react-app.com

# GOD TIER payloads against specific target
./god_tier_tester.sh target.com
```

### Automation Integration
```bash
# Generate encoded payloads for custom testing
python3 advanced_encoder.py "your_payload" akamai > encoded_variants.txt

# Check service status before large-scale testing
python3 service_checker.py && ./ultimate_tester.sh -t target.com
```

### Custom Payload Development
```python
# Add custom GOD TIER payload
custom_payload = "your_advanced_payload_here"
python3 advanced_encoder.py "$custom_payload" generic
```

## 🔍 Troubleshooting

### Common Issues
1. **External tools not found**: Install all prerequisite tools
2. **Service timeouts**: Check internet connection and service status
3. **Permission denied**: Ensure scripts are executable (`chmod +x`)
4. **Rate limiting**: Increase delays between requests

### Debug Mode
Enable verbose output:
```bash
export XSS_VIBES_DEBUG=1
./ultimate_tester.sh -t target.com
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/your-repo/xss-vibes.git
cd xss-vibes
pip install -e .
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**XSS Vibes is intended for authorized security testing only.** 

- Only test applications you own or have explicit permission to test
- Always follow responsible disclosure practices
- Respect rate limits and terms of service
- Use this tool ethically and legally

## 🏆 Achievements

- ✅ **15+ External Tool Integrations**
- 🔥 **10 GOD TIER Evasion Techniques** 
- 🛡️ **8 WAF Types Supported**
- 🎯 **9 Vulnerability Categories**
- 📊 **100% Tool Availability**
- 🚀 **Real-time Service Monitoring**

## 📞 Support

- 📧 Email: security@xssvibes.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-repo/xss-vibes/issues)
- 💬 Discord: [XSS Vibes Community](https://discord.gg/xssvibes)

---

**🔥 XSS Vibes - Where Advanced Security Testing Meets Innovation** 🔥
