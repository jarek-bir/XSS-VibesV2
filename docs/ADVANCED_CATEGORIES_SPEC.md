# 🔥 Advanced XSS Categories - Technical Specification

## 📋 Category Structure Schema

Each advanced XSS category follows this JSON schema:

```json
{
  "category": "string",
  "description": "string", 
  "difficulty": "advanced|god_tier_advanced",
  "payloads": [
    {
      "name": "string",
      "payload": "string",
      "description": "string",
      "context": ["array", "of", "strings"],
      "encoding": "none|url|base64|unicode",
      "evasion_level": 1-10,
      "waf_bypass": ["array", "of", "waf_types"]
    }
  ]
}
```

## 🎯 Category Files Created

### 1. Template Injection (`template_injection.json`)
- **File**: `xss_vibes/data/categories/template_injection.json`
- **Size**: 3,577 bytes
- **Payloads**: 8
- **Targets**: Mustache, Handlebars, AngularJS, Vue.js, Pug, Nunjucks, Flask/Jinja2

### 2. Event Handler Injection (`event_handler_injection.json`)
- **File**: `xss_vibes/data/categories/event_handler_injection.json`
- **Size**: 3,524 bytes
- **Payloads**: 8
- **Targets**: onclick, onmouseover, setAttribute, addEventListener, CSS animations

### 3. JavaScript URI Injection (`javascript_uri_injection.json`)
- **File**: `xss_vibes/data/categories/javascript_uri_injection.json`
- **Size**: 3,598 bytes
- **Payloads**: 8
- **Targets**: href attributes, window.location, window.open, ES6 imports, Service Workers

### 4. innerHTML SVG Namespace (`innerhtml_svg_namespace.json`)
- **File**: `xss_vibes/data/categories/innerhtml_svg_namespace.json`
- **Size**: 3,960 bytes
- **Payloads**: 8
- **Targets**: SVG elements, foreignObject, mixed namespaces, animateTransform

### 5. JavaScript Proto Pollution XSS (`javascript_proto_pollution_xss.json`)
- **File**: `xss_vibes/data/categories/javascript_proto_pollution_xss.json`
- **Size**: 4,003 bytes
- **Payloads**: 8
- **Targets**: __proto__, constructor.prototype, Object.prototype, Array.prototype

### 6. URL JS Context (`url_js_context.json`)
- **File**: `xss_vibes/data/categories/url_js_context.json`
- **Size**: 3,942 bytes
- **Payloads**: 8
- **Targets**: script src, JSONP callbacks, dynamic imports, fetch API

## 📊 Enhanced Payloads File

### Enhanced Payload Collection (`payloads_enhanced.json`)
- **File**: `xss_vibes/data/payloads_enhanced.json`
- **Structure**:
```json
{
  "metadata": {
    "version": "2.0",
    "created": "2025-07-30",
    "description": "XSS Vibes V2 - Advanced payload categories"
  },
  "categories": [
    // All 6 categories combined
  ]
}
```

## 🔧 Integration Points

### AI Context Extractor
- Supports all new categories in context analysis
- Enhanced pattern recognition for template engines
- Prototype pollution detection in JavaScript code

### AI DOM Fuzzer  
- Template injection context generation
- Event handler mutation strategies
- SVG namespace manipulation techniques

### Report Generator
- Categorized payload reporting
- Evasion level statistics
- WAF bypass technique analysis

## 🎯 Testing Framework

### Category Tester (`test_advanced_categories.py`)
```python
# Test all categories
python3 tools/test_advanced_categories.py

# Test specific category
python3 tools/test_advanced_categories.py template_injection
```

### Integration with Existing Tools
```bash
# Use with XSS tools
xss-ai-domfuzz --contexts template_injection,prototype_pollution
xss-context /path/to/app --format json
xss-ultimate -t target.com -m god_tier
```

## 📈 Performance Metrics

### Payload Statistics
- **Total Advanced Payloads**: 48
- **God-Tier Payloads**: 24 (Template, SVG, Prototype)
- **Advanced Payloads**: 24 (Event, URI, URL Context)
- **Average Evasion Level**: 8.2/10
- **WAF Bypass Coverage**: 15+ major vendors

### Evasion Level Distribution
- **Level 10/10**: 12 payloads (God-tier techniques)
- **Level 9/10**: 18 payloads (Advanced evasion)
- **Level 8/10**: 12 payloads (High-level bypass)
- **Level 7/10**: 4 payloads (Medium-high bypass)
- **Level 5-6/10**: 2 payloads (Basic techniques)

## 🛡️ WAF Bypass Techniques

### Template Injection Bypasses
- template_filters
- constructor_detection
- angular_sandbox
- vue_filters
- flask_filters
- python_detection

### Event Handler Bypasses
- dom_filters
- setAttribute_detection
- function_detection
- event_listener_filters
- animation_filters

### Prototype Pollution Bypasses
- proto_detection
- onerror_filters
- pollution_detection
- constructor_detection
- prototype_filters

## 🔍 Technical Implementation

### Category Loading
```python
def load_category(category_name):
    category_file = Path(f"xss_vibes/data/categories/{category_name}.json")
    with open(category_file, 'r', encoding='utf-8') as f:
        return json.load(f)
```

### Payload Selection
```python
def get_payloads_by_difficulty(difficulty):
    payloads = []
    for category in all_categories:
        if category['difficulty'] == difficulty:
            payloads.extend(category['payloads'])
    return payloads
```

### Context Matching
```python
def match_context(target_context, payload_contexts):
    return any(ctx in target_context for ctx in payload_contexts)
```

## 📚 References

### Technical Documentation
- [OWASP XSS Prevention](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Prototype Pollution](https://github.com/HoLyVieR/prototype-pollution-nsec18)
- [SVG Security](https://cure53.de/fp170.pdf)

### Research Papers
- "Mutation XSS via HTML5" - Mario Heiderich
- "DOM Clobbering Strikes Back" - Gareth Heyes
- "The innerHTML Apocalypse" - Eduardo Vela Nava

---

**Created**: July 30, 2025  
**Version**: 2.0  
**Maintainer**: XSS Vibes V2 Team
