# 🎯 XSS Vibes AI Tools Demo

## AI Context Extractor 🧠

```bash
# Analyze single JavaScript file
python3 scripts/ai_context_extractor.py test.js

# Analyze entire directory
python3 scripts/ai_context_extractor.py /path/to/js/project --format json -o analysis.json

# Focus on specific extensions
python3 scripts/ai_context_extractor.py . -e .js .jsx .ts .tsx
```

### Sample JavaScript to Test:
```javascript
// test.js - Sample code with various XSS contexts
import React, { useEffect, useState } from 'react';

const App = () => {
  const [data, setData] = useState('');
  
  useEffect(() => {
    // Vulnerable: Direct innerHTML assignment
    document.getElementById('content').innerHTML = data;
    
    // Vulnerable: eval usage
    eval(userInput);
    
    // Vulnerable: dangerouslySetInnerHTML
    return <div dangerouslySetInnerHTML={{__html: userContent}} />;
  }, [data]);

  // Web Components
  customElements.define('my-element', class extends HTMLElement {
    connectedCallback() {
      this.attachShadow({mode: 'open'});
      this.shadowRoot.innerHTML = untrustedData; // Vulnerable
    }
  });

  // JSONP callback
  window.callback = function(response) {
    eval('processData(' + response + ')'); // Vulnerable
  };

  return <div id="content"></div>;
};
```

## AI DOM Fuzzer 🎯

```bash
# Analyze file and generate targeted payloads
python3 xss_vibes/ai_domfuzz.py --input test.js --max-payloads 30

# Analyze code string directly
python3 xss_vibes/ai_domfuzz.py --content "useEffect(() => eval(data), [])" --format burp

# Generate cURL test commands
python3 xss_vibes/ai_domfuzz.py --input app.js --format curl --output tests.sh

# Use custom payload directory
python3 xss_vibes/ai_domfuzz.py --input test.js --data-dir xss_vibes/data/
```

### Expected Output:
```
🧠 XSS Vibes - AI DOM Fuzzer
==================================================
📊 Analysis Results:
   Detected contexts: 4
   Selected payloads: 30
   Coverage score: 95.0%

🎯 Top Contexts:
   useEffect (priority: 9, matches: 1)
   eval_contexts (priority: 10, matches: 2)
   shadowRoot (priority: 8, matches: 1)
   innerHTML_sinks (priority: 9, matches: 1)

💡 Recommendations:
   🚨 HIGH PRIORITY: Focus on 3 critical contexts
     🎯 useEffect: React useEffect hook injection
     🎯 eval_contexts: Dynamic code execution
     🎯 shadowRoot: Shadow DOM injection
   🔀 Generated 15 payload mutations for bypass attempts
   ⚡ Detected eval contexts - prioritize code injection payloads
   ⚛️ React hooks detected - test component lifecycle injection
   🌑 Shadow DOM detected - test encapsulation bypass
```

## Report Generator 📊

```bash
# Generate comprehensive HTML report
python3 scripts/report_gen.py -r scan_results.json -t comprehensive

# Generate template-specific report
python3 scripts/report_gen.py -r results.json -t template --template react_binding

# Generate payload-specific report  
python3 scripts/report_gen.py -r results.json -t payload --payload "<script>alert(1)</script>"

# Custom output directory
python3 scripts/report_gen.py -r results.json -o /tmp/reports/
```

### Sample Results JSON Format:
```json
{
  "session": {
    "session_id": "scan_20250129_143000",
    "start_time": "2025-01-29T14:30:00",
    "end_time": "2025-01-29T14:35:00",
    "target_urls": ["https://example.com"],
    "total_tests": 100,
    "successful_tests": 85,
    "failed_tests": 15,
    "vulnerabilities_found": 12,
    "templates_used": ["react_binding", "dom_sinks", "iframe_sandbox"],
    "payload_categories": ["basic_xss", "polyglots", "react_hooks"]
  },
  "results": [
    {
      "payload": "<script>alert(1)</script>",
      "template": "react_binding",
      "url": "https://example.com/test",
      "method": "POST",
      "parameter": "content",
      "status_code": 200,
      "response_time": 245.5,
      "content_length": 1024,
      "reflected": true,
      "executed": true,
      "waf_blocked": false,
      "evidence": "alert(1) executed",
      "timestamp": "2025-01-29T14:30:15"
    }
  ]
}
```

## Integration Examples 🔧

### 1. Full AI-Powered Workflow:
```bash
# Step 1: Analyze target application
python3 scripts/ai_context_extractor.py /path/to/webapp -o context_analysis.json

# Step 2: Generate targeted payloads
python3 xss_vibes/ai_domfuzz.py --input /path/to/main.js --format json -o targeted_payloads.json

# Step 3: Run XSS Vibes scan with results
python3 -m xss_vibes https://target.com --enhanced-payloads --session-file scan_session.json

# Step 4: Generate comprehensive report
python3 scripts/report_gen.py -r scan_session.json -t comprehensive -o reports/
```

### 2. CI/CD Integration:
```bash
#!/bin/bash
# ci_xss_check.sh - Automated XSS testing in CI/CD

echo "🔍 AI Context Analysis..."
python3 scripts/ai_context_extractor.py src/ --format json -o ci_analysis.json

RISK_SCORE=$(jq '.summary.total_risk_score' ci_analysis.json)
if [ "$RISK_SCORE" -gt 200 ]; then
    echo "🚨 High risk detected, generating targeted payloads..."
    python3 xss_vibes/ai_domfuzz.py --input src/main.js --format json -o ci_payloads.json
    
    echo "🎯 Running targeted XSS scan..."
    python3 -m xss_vibes $TEST_URL --payload-file ci_payloads.json --session-file ci_results.json
    
    echo "📊 Generating security report..."
    python3 scripts/report_gen.py -r ci_results.json -o security_reports/
fi
```

### 3. Bug Bounty Automation:
```bash
# Bug bounty workflow
TARGET_DOMAIN="example.com"

echo "🧠 Smart reconnaissance..."
python3 scripts/ai_context_extractor.py $TARGET_DOMAIN/assets/ -o recon.json

echo "🎯 AI-powered payload generation..."
python3 xss_vibes/ai_domfuzz.py --input recon.json --max-payloads 100 --format burp -o bb_payloads.txt

echo "💥 Mass XSS testing..."
python3 -m xss_vibes $TARGET_DOMAIN --payload-file bb_payloads.txt --threads 10 --session-file bb_results.json

echo "📋 Professional report generation..."
python3 scripts/report_gen.py -r bb_results.json -t comprehensive -o bounty_reports/
```

## Advanced Features 🚀

### Custom Context Detection:
```python
# Extend AI Context Extractor with custom patterns
from scripts.ai_context_extractor import AIContextExtractor

extractor = AIContextExtractor()
extractor.context_patterns["custom_framework"] = {
    "patterns": [r"myFramework\.render", r"customTemplate\s*="],
    "payload_types": ["template_injection"],
    "priority": 8,
    "description": "Custom framework injection"
}
```

### Custom Fuzzing Strategies:
```python
# Add custom DOM fuzzing mutations
from xss_vibes.ai_domfuzz import AIDOMFuzzer

fuzzer = AIDOMFuzzer()
fuzzer.mutation_strategies["custom_bypass"] = {
    "description": "Custom WAF bypass",
    "mutations": [
        lambda p: p.replace('script', 'scr\x00ipt'),
        lambda p: p.replace('alert', 'ale\u0000rt')
    ]
}
```

### Template Report Customization:
```python
# Custom report templates
from scripts.report_gen import ReportGenerator

generator = ReportGenerator()
generator.css_styles += """
.custom-vuln { background: linear-gradient(45deg, #ff6b6b, #ffd93d); }
"""
```

## Output Samples 📋

### AI Context Analysis Results:
```
🎯 Quick Summary:
   Risk score: 85/100 (HIGH)
   Best template: react_binding
   Key contexts: 3 DOM sinks, 2 dynamic execution

💡 Recommendations:
🎯 PRIMARY: Use template 'react_binding' (confidence: 90%)
🔥 Test DOM sinks with innerHTML/outerHTML payloads (3 found)
⚡ Test dynamic execution contexts with eval/Function payloads (2 found)
🔸 Test dangerouslySetInnerHTML and JSX injection points
```

### Generated HTML Report Features:
- **Interactive Charts**: Vulnerability distribution, template success rates, timeline
- **Sortable Tables**: All test results with advanced filtering
- **Export Options**: JSON, CSV, XML, PDF formats
- **Risk Assessment**: Color-coded severity levels
- **Template Analysis**: Success rates per template
- **Payload Effectiveness**: Most successful payloads ranked
- **Professional Layout**: Modern responsive design with charts and graphs
