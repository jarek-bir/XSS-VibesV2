# 🔍 XSS Vibes V2 - Development Interface Hunter

Specialized module for discovering development, staging, and testing environments that are often overlooked during security assessments.

## 🎯 What It Finds

### Development Environments
- `dev.example.com`, `development.example.com`, `staging.example.com`
- `test.example.com`, `qa.example.com`, `beta.example.com`
- Development paths: `/dev/`, `/staging/`, `/test/`, `/debug/`

### Framework-Specific Interfaces
- **Symfony**: `/app_dev.php`, `/web/app_dev.php`
- **Laravel**: `/dev/`, `/.env.dev`
- **Node.js**: Development servers, debug endpoints
- **Django**: Debug mode interfaces

### API Development Endpoints
- `/api/dev/`, `/api/test/`, `/api/staging/`
- `/v1/dev/`, `/v2/test/`
- GraphQL development endpoints
- Swagger/OpenAPI dev documentation

### Developer Information Extraction
- Author names and contact information
- Development dates and version history
- Environment configuration details
- Debug information and stack traces

## 🚀 Quick Usage

### Standalone Dev Hunter
```bash
# Hunt single domain
./tools/dev-hunter example.com

# Hunt multiple domains
./tools/dev-hunter example.com test.com staging.com

# Custom output directory
./tools/dev-hunter example.com -o my_dev_scan

# Verbose mode
./tools/dev-hunter example.com -v
```

### Integrated with Main Crawler
```bash
# Dev hunting is automatically included in main scans
./tools/xss-hunt example.com

# Full crawler with dev hunting
./tools/xss-crawler -d example.com -w comprehensive_scan
```

### Using Makefile
```bash
# Quick dev hunt
make hunt DOMAIN=example.com

# Custom dev hunt
make dev-hunt DOMAIN=example.com
```

## 📊 Example Output

### Real Case: secure.trip.com
```
🔍 Development Interface Discovery

URL: https://secure.trip.com/dev/test.html
Status: 200
Confidence: 85%

Developer Info:
  👤 Author: chen.yun
  📅 Date: 2025-04-16 10:54:25
  📝 Last Editor: chen.yun
  🕐 Last Edit: 2025-04-16 10:55:50

Detection Indicators:
  ✓ URL contains 'dev' keyword
  ✓ Simple "Hello World" test page
  ✓ HTML developer comments found
  ✓ Content length indicates test page
```

## 🔧 Detection Patterns

### URL Patterns
- **Subdomains**: `dev.*`, `staging.*`, `test.*`, `qa.*`, `beta.*`
- **Paths**: `/dev/`, `/staging/`, `/test/`, `/debug/`, `/_dev/`
- **Files**: `app_dev.php`, `test.html`, `debug.js`, `.env.dev`

### Content Signatures
- Developer comments (`@Author`, `@Date`, `@LastEditor`)
- Debug mode indicators (`debug=true`, `NODE_ENV=development`)
- Test page content (`Hello World`, `Test Page`, `Coming Soon`)
- Framework debug output

### Response Headers
- Development server headers
- Debug-related headers (`x-debug`, `x-dev`)
- Environment indicators

## 📈 Confidence Scoring

### High Confidence (70%+)
- Multiple detection indicators
- Developer information extracted
- Known development patterns

### Medium Confidence (40-69%)
- Some development indicators
- Partial pattern matches
- Suspicious response patterns

### Low Confidence (30-39%)
- Weak indicators
- Possible false positives
- Borderline detections

## 🎛️ Configuration

### Pattern Customization
You can extend detection patterns by modifying `xss_vibes/dev_hunter.py`:

```python
"dev_subdomains": [
    "dev", "development", "staging", "test", "qa", "beta",
    # Add your custom patterns here
    "internal", "corp", "admin-test"
],

"dev_paths": [
    "/dev/", "/staging/", "/test/",
    # Add custom paths
    "/internal/", "/corp-dev/"
]
```

### Performance Tuning
```python
# Adjust concurrent requests
await hunter.hunt_dev_interfaces(domains, max_concurrent=20)

# Custom timeout and retry settings
# Modify in DevInterfaceHunter.__init__()
```

## 📁 Output Structure

```
dev_hunt_results/
├── dev_interfaces.json      # Raw JSON results
├── dev_interfaces.txt       # Human-readable summary
├── dev_interfaces.html      # Interactive HTML report
└── high_confidence.txt      # Filtered high-confidence results
```

### JSON Schema
```json
{
  "url": "https://dev.example.com",
  "status_code": 200,
  "is_dev_interface": true,
  "confidence": 85,
  "dev_info": {
    "authors": ["chen.yun"],
    "dates": ["2025-04-16 10:54:25"],
    "environment": ["development"]
  },
  "indicators": [
    {"type": "url_keyword", "keyword": "dev"},
    {"type": "content_pattern", "pattern": "@Author"},
    {"type": "header", "header": "server: nginx/dev"}
  ]
}
```

## 🔗 Integration Examples

### With Main XSS Scanner
```python
from xss_vibes.dev_hunter import DevInterfaceHunter
from xss_vibes.scanner import XSSScanner

# Hunt dev interfaces first
hunter = DevInterfaceHunter()
dev_interfaces = await hunter.hunt_dev_interfaces(["example.com"])

# Extract URLs for XSS testing
dev_urls = [interface['url'] for interface in dev_interfaces]

# Run XSS scans on dev interfaces
scanner = XSSScanner()
results = await scanner.scan_urls(dev_urls)
```

### Custom Pattern Detection
```python
# Add custom patterns for your target
hunter = DevInterfaceHunter()
hunter.dev_patterns["dev_subdomains"].extend([
    "internal", "corp", "admin-test", "api-dev"
])

# Hunt with custom patterns
results = await hunter.hunt_dev_interfaces(["target.com"])
```

## 🛡️ Security Impact

### Why Development Interfaces Matter
1. **Exposed Debug Information**: Stack traces, configuration details
2. **Weak Authentication**: Often no auth or default credentials
3. **Latest Code**: May contain unreleased features/vulnerabilities
4. **Sensitive Data**: Database connections, API keys, internal URLs
5. **Privilege Escalation**: Admin panels, internal tools

### Common Vulnerabilities Found
- Information disclosure through debug output
- Authentication bypasses
- Exposed configuration files
- Internal API endpoints
- Administrative functions

## ⚡ Performance Tips

### Fast Scanning
```bash
# Reduce concurrent requests for slower targets
./tools/dev-hunter example.com -c 5

# Focus on high-value patterns only
# Modify patterns to reduce noise
```

### Large-Scale Hunting
```bash
# Process multiple domains from file
cat domains.txt | xargs -I {} ./tools/dev-hunter {}

# Parallel processing
parallel -j 5 ./tools/dev-hunter {} ::: domain1.com domain2.com domain3.com
```

## 🔄 Updates and Maintenance

### Pattern Updates
Development patterns evolve with frameworks and practices. Regular updates include:
- New framework-specific patterns
- Updated subdomain patterns
- Enhanced content signatures
- Improved confidence scoring

### Contributing Patterns
Found new development patterns? Contribute them back:
1. Add patterns to `dev_patterns` in `dev_hunter.py`
2. Test with known development environments
3. Submit pull request with examples

## 📚 Related Tools

- **Main Crawler**: `tools/advanced_crawler.py`
- **Endpoint Hunter**: `tools/endpoint_hunter.py`
- **XSS Scanner**: Core XSS Vibes functionality
- **Subdomain Enumeration**: Integration with external tools

## 🎯 Real-World Examples

### Case Study: Trip.com
- **Target**: secure.trip.com
- **Finding**: Development test interface
- **Impact**: Developer information disclosure
- **Pattern**: Simple test page with HTML comments

### Case Study: E-commerce Platform
- **Target**: staging.shop.example.com
- **Finding**: Full staging environment mirror
- **Impact**: Access to unreleased features
- **Pattern**: Staging subdomain with full application

This specialized hunter gives you the edge in discovering those hidden development interfaces that other scanners miss! 🔥
