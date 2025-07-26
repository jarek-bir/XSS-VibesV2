# Advanced Features Documentation

## 🎭 Advanced Evasion Techniques (Encoding Engine)

XSS Vibes v2.0 includes a sophisticated encoding engine with 19 different encoding techniques for bypassing Web Application Firewalls (WAFs).

### Available Encoding Types

1. **URL Encoding** - Standard URL encoding (%20, %3C, etc.)
2. **Double URL Encoding** - Double URL encoding (%253C, %2520, etc.)
3. **HTML Entity Encoding** - HTML entity encoding (&lt;, &gt;, &#x3C;, etc.)
4. **Unicode Encoding** - Unicode escape sequences (\u003C, \u003E, etc.)
5. **Hexadecimal Encoding** - Hexadecimal encoding (\x3C, \x3E, etc.)
6. **Octal Encoding** - Octal encoding (\074, \076, etc.)
7. **Base64 Encoding** - Base64 encoding with eval wrapper
8. **UTF-7 Encoding** - UTF-7 encoding for IE/Edge bypass
9. **UTF-16 Encoding** - UTF-16 encoding
10. **JSON Unicode Escapes** - JSON Unicode escapes
11. **CSS Character Encoding** - CSS character encoding (\3C, \3E, etc.)
12. **JavaScript String Encoding** - JavaScript string encoding
13. **Mixed Case Obfuscation** - Mixed case obfuscation
14. **Character Entity Substitution** - Character entity substitution
15. **HTML/JS Comment Insertion** - HTML/JS comment insertion
16. **Whitespace Character Substitution** - Whitespace character substitution
17. **String Concatenation** - String concatenation
18. **Dynamic Evaluation Wrapper** - Dynamic evaluation wrapper
19. **String.fromCharCode Encoding** - String.fromCharCode encoding

### Usage Examples

#### Basic Encoding
```bash
# Enable basic encoding
xss-vibes scan --encoding https://example.com

# Use specific encoding types
xss-vibes scan --encoding --encoding-types unicode,base64,utf7 https://example.com

# Use high-evasion mode (only high-scoring techniques)
xss-vibes scan --high-evasion https://example.com
```

#### Context-Aware Encoding
```bash
# Enable context-aware encoding (automatically detects injection context)
xss-vibes scan --context-aware https://example.com

# Combine with specific encoding types
xss-vibes scan --context-aware --encoding-types fromcharcode,eval https://example.com
```

#### Encoding Analysis
```bash
# Analyze a payload's evasion potential
xss-vibes encoding --analyze "<script>alert(1)</script>"

# Test payload with all encoding techniques
xss-vibes encoding --test-payload "<img src=x onerror=alert(1)>"

# List all available encoding types
xss-vibes encoding --list-encodings

# Show encoding demonstration
xss-vibes encoding --demo
```

### Context-Aware Encoding

The engine automatically detects injection contexts and selects optimal encoding:

- **HTML Attribute Context** - Uses attribute-safe encodings
- **JavaScript String Context** - Uses JavaScript-compatible encodings
- **CSS Context** - Uses CSS-specific encodings
- **URL Parameter Context** - Uses URL-safe encodings

### Bypass Scoring

Each encoding technique is scored on bypass potential (1-10):
- **10** - Extremely effective against most WAFs
- **8-9** - Very effective against many WAFs
- **6-7** - Moderately effective
- **1-5** - Basic effectiveness

## 📊 Advanced Reporting

XSS Vibes v2.0 includes a comprehensive reporting system that generates professional security assessment reports.

### Report Formats

1. **HTML** - Professional web-based reports with styling
2. **JSON** - Machine-readable structured reports
3. **CSV** - Spreadsheet-compatible tabular data
4. **Markdown** - Documentation-friendly format

### Report Features

- **Executive Summary** - High-level overview for management
- **Security Statistics** - Detailed metrics and analytics
- **Vulnerability Details** - Comprehensive vulnerability information
- **Risk Assessment** - Automated risk level calculation
- **Technical Details** - In-depth technical information
- **Remediation Guidance** - Specific fix recommendations
- **WAF Detection Results** - WAF identification and bypass status

### Usage Examples

#### Generating Reports During Scan
```bash
# Generate HTML report
xss-vibes scan --report-format html --output report.html https://example.com

# Generate JSON report with technical details
xss-vibes scan --report-format json --include-technical --output report.json https://example.com

# Generate CSV report without payloads (for compliance)
xss-vibes scan --report-format csv --no-include-payloads --output report.csv https://example.com

# Generate Markdown report with custom title
xss-vibes scan --report-format markdown --report-title "Security Assessment - Example.com" --output report.md https://example.com
```

#### Report Configuration Options
```bash
# Include/exclude payloads
--include-payloads / --no-include-payloads

# Include/exclude technical details
--include-technical / --no-include-technical

# Include/exclude executive summary
--executive-summary / --no-executive-summary

# Custom report title
--report-title "Custom Title"
```

### Report Structure

#### HTML Reports
- Professional styling with CSS
- Executive summary with risk assessment
- Interactive vulnerability details
- Technical information sections
- Remediation recommendations
- Statistics and charts

#### JSON Reports
- Machine-readable structured data
- Complete vulnerability information
- Metadata and statistics
- Nested data structures for complex analysis
- API-friendly format

#### CSV Reports
- Spreadsheet-compatible format
- Tabular vulnerability data
- Suitable for compliance reporting
- Easy import into other tools

#### Markdown Reports
- Documentation-friendly format
- Version control friendly
- Easy to include in documentation
- GitHub/GitLab compatible

### Risk Assessment

Reports automatically calculate risk levels based on:
- Vulnerability severity (Critical, High, Medium, Low)
- Number of vulnerabilities found
- Affected parameters and URLs
- WAF bypass success rates

Risk levels:
- **CRITICAL** - Immediate action required
- **HIGH** - Address within 1 week
- **MEDIUM** - Address within 1 month
- **LOW** - Address during next security review

### Integration Examples

#### CI/CD Pipeline Integration
```bash
# Generate JSON report for automated processing
xss-vibes scan --report-format json --output scan_results.json $TARGET_URL

# Parse results for CI/CD decisions
python -c "
import json
with open('scan_results.json') as f:
    report = json.load(f)
    if report['statistics']['by_severity']['critical'] > 0:
        exit(1)  # Fail build on critical vulnerabilities
"
```

#### Security Dashboard Integration
```bash
# Generate comprehensive HTML dashboard
xss-vibes scan \
  --report-format html \
  --include-technical \
  --executive-summary \
  --report-title "Daily Security Scan - $(date)" \
  --output "dashboard/scan_$(date +%Y%m%d).html" \
  $TARGET_URLS
```

## 🔧 Combined Usage

You can combine encoding and reporting features for comprehensive security testing:

```bash
# Complete security assessment with encoding and reporting
xss-vibes scan \
  --high-evasion \
  --context-aware \
  --encoding-types unicode,base64,fromcharcode \
  --report-format html \
  --include-technical \
  --report-title "Complete Security Assessment" \
  --output security_report.html \
  https://target.example.com

# Stealth scan with advanced evasion and reporting
xss-vibes scan \
  --stealth \
  --encoding \
  --encoding-variants 10 \
  --report-format json \
  --output stealth_scan.json \
  https://target.example.com
```

## 🎯 Best Practices

### Encoding Selection
- Use `--high-evasion` for maximum WAF bypass potential
- Use `--context-aware` for intelligent encoding selection
- Combine multiple encoding types for better coverage
- Start with basic encodings and escalate if needed

### Report Generation
- Use HTML reports for management presentations
- Use JSON reports for automation and integration
- Use CSV reports for compliance and spreadsheet analysis
- Use Markdown reports for documentation

### Performance Considerations
- High-evasion mode uses more resources
- Multiple encoding variants increase scan time
- Context-aware encoding adds analysis overhead
- Consider using stealth mode for sensitive targets

## 📝 Configuration Files

You can create configuration files to save common settings:

```json
{
  "encoding": {
    "enabled": true,
    "types": ["unicode", "base64", "fromcharcode"],
    "variants": 5,
    "context_aware": true,
    "high_evasion": false
  },
  "reporting": {
    "format": "html",
    "include_payloads": true,
    "include_technical": true,
    "executive_summary": true,
    "custom_title": "Security Assessment Report"
  },
  "scan": {
    "stealth": true,
    "threads": 1,
    "timeout": 15
  }
}
```

This comprehensive documentation covers both the Advanced Evasion Techniques (Encoding Engine) and Advanced Reporting features implemented in XSS Vibes v2.0.
