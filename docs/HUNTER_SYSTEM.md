# 🕷️ XSS Vibes V2 - Advanced Hunter System

Complete reconnaissance framework for discovering hidden endpoints, development interfaces, and API vulnerabilities.

## 🎯 Hunter Modules

### 🔍 Development Interface Hunter
Discovers development, staging, and testing environments:
```bash
./tools/dev-hunter example.com
make dev-hunt DOMAIN=example.com
```
**What it finds:**
- Dev/staging subdomains (`dev.example.com`, `staging.example.com`)
- Development paths (`/dev/`, `/staging/`, `/debug/`)
- Framework debug interfaces (`app_dev.php`, `debug.html`)
- Developer information (names, dates, versions)

### 🔍 API Endpoint Hunter
Specialized discovery of REST APIs and web services:
```bash
./tools/api-hunter example.com
make api-hunt DOMAIN=example.com
```
**What it finds:**
- REST API endpoints (`/api/`, `/restapi/`, `/soa2/`)
- JSON/XML endpoints (`.json`, `.xml`, `getToken.json`)
- Mobile APIs (`/mobile/`, `/m/api/`)
- High-value endpoints (authentication, configuration, user data)

### 🕷️ Advanced Crawler
Osmedeus-style comprehensive reconnaissance:
```bash
./tools/xss-crawler -d example.com -w my_scan
./tools/xss-hunt example.com
make hunt DOMAIN=example.com
```
**What it finds:**
- All endpoints via crawling
- Fofa/Shodan integration
- Vulnerability scanning with Nuclei/Jaeles
- Complete reconnaissance pipeline

## 🔥 Real-World Success Cases

### Case Study: Trip.com Development Interface
**Target**: `secure.trip.com`
**Finding**: Development test interface with exposed developer information
```
URL: https://secure.trip.com/dev/test.html
Developer: chen.yun
Date: 2025-04-16 10:54:25
Risk: Information Disclosure
```

### Case Study: Ctrip.com API Discovery
**Target**: `m.ctrip.com`
**Findings**: Active API endpoints with token exposure
```
1. Token Generation API
   - Endpoint: /restapi/soa2/11470/getToken.json
   - Status: ✅ Functional
   - Data: {"token": "44879439", "scriptUrl": "/code/ubt/fp-em9.js"}
   - Risk: Token exposure for fingerprinting

2. App Configuration API
   - Endpoint: /restapi/soa2/18088/getAppConfig.json
   - Status: ✅ Active (POST required)
   - Error: "请求体不能为空，且必须为JSON格式"
   - Risk: Configuration data exposure
```

## 🚀 Quick Start

### Individual Hunters
```bash
# Development interfaces
./tools/dev-hunter ctrip.com trip.com

# API endpoints
./tools/api-hunter ctrip.com

# Full reconnaissance
./tools/xss-hunt ctrip.com
```

### Using Makefile
```bash
# Setup tools
make crawler

# Quick hunts
make dev-hunt DOMAIN=ctrip.com
make api-hunt DOMAIN=ctrip.com
make hunt DOMAIN=ctrip.com

# Advanced searches
make fofa QUERY='title="admin panel"'
make shodan QUERY='http.title:login'
```

### Combined Reconnaissance
```bash
# Multi-source intelligence gathering
./tools/xss-crawler -d ctrip.com \
  -f 'domain="ctrip.com"' \
  -s 'hostname:ctrip.com' \
  -w ctrip_full_scan
```

## 📊 Output Analysis

### Development Interface Results
```
🔍 Development Interface Discovery

URL: https://dev.example.com/test.html
Confidence: 85%
Developer Info:
  👤 Author: chen.yun
  📅 Date: 2025-04-16 10:54:25
  📝 Last Editor: chen.yun
Detection Indicators:
  ✓ URL contains 'dev' keyword
  ✓ HTML developer comments found
  ✓ Simple test page content
```

### API Endpoint Results
```
🔍 API Endpoint Discovery

#### 1. Token Generation API
- **Endpoint**: https://m.ctrip.com/restapi/soa2/11470/getToken.json
- **Method**: GET
- **Status**: ✅ Functional
- **Risk Level**: HIGH
- **Data Exposed**:
  {
    "data.token": "44879439",
    "data.scriptUrl": "/code/ubt/fp-em9.js"
  }
```

## 🎛️ Configuration

### Pattern Customization
Add custom patterns for specific targets:

**Development Interface Patterns** (`xss_vibes/dev_hunter.py`):
```python
"dev_subdomains": [
    "dev", "staging", "test", "qa", "beta",
    # Add target-specific patterns
    "internal", "corp", "admin-dev"
]
```

**API Endpoint Patterns** (`xss_vibes/api_hunter.py`):
```python
"api_paths": [
    "/api/", "/restapi/", "/soa2/",
    # Add framework-specific patterns
    "/your-framework/api/"
]
```

### Performance Tuning
```bash
# Adjust concurrent requests
./tools/dev-hunter example.com -c 10
./tools/api-hunter example.com -c 15

# Verbose output for debugging
./tools/dev-hunter example.com -v
./tools/api-hunter example.com -v
```

## 📁 Output Structure

```
workspace_name/
├── reconnaissance.json          # Combined recon results
├── dev_interfaces/             # Development interface results
│   ├── dev_interfaces.json     # Raw JSON data
│   ├── dev_interfaces.html     # Interactive report
│   └── dev_interfaces.txt      # Human-readable summary
├── api_endpoints/              # API endpoint results
│   ├── api_endpoints.json      # Raw JSON data
│   ├── api_endpoints.html      # Interactive report
│   └── api_report.txt          # Detailed analysis
├── endpoints/                  # Crawled endpoints
│   ├── endpoints.json
│   └── endpoints.txt
└── reports/                    # Final reports
    ├── report.html             # Comprehensive HTML report
    └── summary.json            # Executive summary
```

## 🔗 Integration Examples

### With External Tools
```bash
# Export endpoints for Burp Suite
cat workspace/endpoints/endpoints.txt > burp_targets.txt

# Use with nuclei
nuclei -l workspace/endpoints/endpoints.txt -t ~/nuclei-templates/

# Integration with custom scripts
python3 your_script.py --input workspace/api_endpoints/api_endpoints.json
```

### With XSS Vibes Core
```python
from xss_vibes.dev_hunter import DevInterfaceHunter
from xss_vibes.api_hunter import APIEndpointHunter
from xss_vibes.scanner import XSSScanner

# Discover targets
dev_hunter = DevInterfaceHunter()
api_hunter = APIEndpointHunter()

dev_results = await dev_hunter.hunt_dev_interfaces(["example.com"])
api_results = await api_hunter.hunt_api_endpoints(["example.com"])

# Extract URLs for XSS testing
all_urls = []
all_urls.extend([r['url'] for r in dev_results])
all_urls.extend([r['url'] for r in api_results])

# Run XSS scans
scanner = XSSScanner()
xss_results = await scanner.scan_urls(all_urls)
```

## 🛡️ Security Impact

### Why These Discoveries Matter

**Development Interfaces:**
- Exposed debug information and stack traces
- Weak or missing authentication
- Access to unreleased features
- Internal system information disclosure

**API Endpoints:**
- Authentication token exposure
- Configuration data leakage
- User data access without proper auth
- Internal system architecture disclosure

### Risk Assessment

**HIGH RISK** indicators:
- Token generation endpoints
- Configuration APIs
- User data APIs
- Administrative interfaces

**MEDIUM RISK** indicators:
- Development environments
- Staging interfaces
- Debug endpoints
- Error message disclosure

**LOW RISK** indicators:
- Simple test pages
- Documentation endpoints
- Status/health checks

## ⚡ Performance & Scaling

### Large-Scale Hunting
```bash
# Process multiple domains
cat domains.txt | xargs -P 5 -I {} ./tools/api-hunter {}

# Parallel processing with GNU parallel
parallel -j 5 ./tools/dev-hunter {} ::: domain1.com domain2.com domain3.com

# Background processing
nohup ./tools/xss-hunt example.com > hunt.log 2>&1 &
```

### Resource Management
- **Memory**: ~100MB per hunter instance
- **Network**: Respects rate limits and delays
- **Storage**: ~10-50MB per domain scanned
- **CPU**: Optimized for concurrent async operations

## 🔄 Updates & Maintenance

### Pattern Database Updates
The hunter patterns are continuously updated with:
- New framework-specific endpoints
- Updated subdomain patterns
- Enhanced content signatures
- Improved confidence scoring algorithms

### Contributing Discoveries
Found new patterns? Contribute them:
1. Add patterns to appropriate hunter modules
2. Test with known environments
3. Document with real-world examples
4. Submit pull request

## 📚 Advanced Usage

### Custom Hunter Development
Create specialized hunters for specific targets:

```python
from xss_vibes.api_hunter import APIEndpointHunter

class CustomHunter(APIEndpointHunter):
    def load_custom_patterns(self):
        # Add your target-specific patterns
        return custom_patterns
    
    async def custom_analysis(self, response):
        # Add custom analysis logic
        return analysis
```

### Automation Integration
```bash
# CI/CD pipeline integration
./tools/xss-hunt $TARGET_DOMAIN --output results/
if [ -s results/api_endpoints/api_endpoints.json ]; then
    echo "APIs found - triggering security review"
    # Integrate with your workflow
fi
```

This comprehensive hunter system gives you the reconnaissance capabilities of tools like Osmedeus, specialized for discovering the exact types of interfaces and APIs that led to the Trip.com and Ctrip.com discoveries! 🔥
