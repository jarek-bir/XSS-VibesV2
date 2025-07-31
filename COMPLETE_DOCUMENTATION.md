# XSS Vibes V2 - Kompletna Dokumentacja

![XSS Vibes V2](xss_vibes.png)

## 📋 Spis Treści

1. [Wprowadzenie](#wprowadzenie)
2. [Instalacja i Konfiguracja](#instalacja-i-konfiguracja)
3. [Architektura Systemu](#architektura-systemu)
4. [Narzędzia Discovery](#narzędzia-discovery)
5. [Narzędzia Hunting](#narzędzia-hunting)
6. [Zaawansowane Narzędzia](#zaawansowane-narzędzia)
7. [Pipeline'y Automatyzacji](#pipeliny-automatyzacji)
8. [Konfiguracja API](#konfiguracja-api)
9. [Wordlisty i Payloady](#wordlisty-i-payloady)
10. [Przykłady Użycia](#przykłady-użycia)
11. [Rozwiązywanie Problemów](#rozwiązywanie-problemów)

---

## 🎯 Wprowadzenie

**XSS Vibes V2** to zaawansowana platforma do automatycznego wykrywania podatności XSS, zbudowana w stylu Osmedeus z modułową architekturą i zaawansowanymi możliwościami reconnaissance.

### ✨ Kluczowe Funkcjonalności

- 🔍 **Target Discovery**: Shodan + Fofa integration
- 🕷️ **Advanced Crawling**: Osmedeus-style reconnaissance
- 📚 **Wordlist Hunting**: Specialized SOA2 + API hunting
- 🎯 **Nuclei Integration**: Template-based vulnerability scanning  
- 📊 **Real-time Monitoring**: Continuous target discovery
- 🔬 **Mass Validation**: Bulk endpoint verification
- 🚀 **Full Automation**: Complete pipeline execution

### 🏗️ Architektura

```
XSS Vibes V2/
├── xss_vibes/               # Core framework
├── tools/                   # Standalone tools
├── wordlists/              # Specialized wordlists
├── data/                   # Payloads and configurations
└── config/                 # API keys and settings
```

---

## 🛠️ Instalacja i Konfiguracja

### Wymagania Systemowe

- Python 3.9+
- Linux/Unix environment
- 4GB+ RAM (dla mass validation)
- Klucze API: Shodan, Fofa

### Instalacja

```bash
git clone https://github.com/jarek-bir/XSS-VibesV2.git
cd XSS-VibesV2
make install
```

### Konfiguracja API Keys

Utwórz plik `~/.env_secrets`:

```bash
# Fofa Configuration
export FOFA_EMAIL="your-email@example.com"
export FOFA_KEY="your-fofa-api-key"

# Shodan Configuration  
export SHODAN_API_KEY="your-shodan-api-key"

# Opcjonalne
export NUCLEI_PATH="/usr/local/bin/nuclei"
```

---

## 🕸️ Architektura Systemu

### Core Components

#### 1. **Discovery Engine** (`tools/simple-target-hunter`)
- Multi-source target discovery
- Shodan + Fofa integration
- Predefined search strategies
- Rate limiting and error handling

#### 2. **Hunting Framework** (`tools/wordlist-hunter`)
- SOA2 endpoint discovery (Ctrip patterns)
- API endpoint hunting
- Development interface detection
- Custom wordlist support

#### 3. **Validation Engine** (`tools/mass-validator`)
- Bulk endpoint verification
- Technology detection
- Security headers analysis
- Performance metrics

#### 4. **Security Scanner** (`tools/nuclei-runner`)
- Nuclei template integration
- XSS-focused scanning
- Custom template support
- Result aggregation

#### 5. **Monitoring Pipeline** (`tools/realtime-monitor`)
- Continuous target discovery
- SQLite-based tracking
- Automated scanning cycles
- Notification support

---

## 🔍 Narzędzia Discovery

### Target Discovery

#### Fofa Search
```bash
# Basic admin panel search
make fofa QUERY='title="admin"'

# Travel industry targets
make fofa QUERY='body="restapi/soa2"'

# Custom query
./tools/fofa-searcher -q 'title="ctrip"' --max-results 100
```

#### Shodan Search  
```bash
# Login page discovery
make shodan QUERY='http.title:"login"'

# Nginx servers
make shodan QUERY='http.component:"nginx"'

# Custom search
./tools/shodan-searcher -q 'http.title:"admin"' --max-results 50
```

#### Combined Discovery
```bash
# SOA2 focused discovery
make target-hunt-soa2

# General target hunting
make target-hunt

# Custom strategy
./tools/simple-target-hunter -s chinese_travel
```

### Discovery Strategies

#### 1. **soa2_discovery**
- `body="restapi/soa2"`
- `body="/soa2/"`  
- `title="ctrip" || title="trip.com"`

#### 2. **chinese_travel**
- `title="携程"` (Ctrip Chinese)
- `body="去哪儿"` (Qunar)
- `title="飞猪"` (Fliggy)

#### 3. **admin_panels**
- `title="admin"`
- `title="管理"`
- `body="admin panel"`

---

## 🎯 Narzędzia Hunting

### Wordlist-Based Hunting

#### SOA2 Hunting (Specialized)
```bash
# Target specific domain
make wordlist-soa2 DOMAIN=app.ctrip.com

# Full SOA2 hunt
make soa2-hunt

# Cross-domain hunting
make cross-domain-hunt
```

#### API Endpoint Discovery
```bash
# API focused hunt
make api-hunt DOMAIN=api.example.com

# Combined hunting
make wordlist-hunt DOMAIN=example.com TYPE=all
```

### Wordlist Categories

#### 1. **SOA2 Endpoints** (`wordlists/soa2_endpoints.txt`)
- 115 unique endpoint patterns
- Based on real Ctrip.com discoveries
- Service-specific paths

#### 2. **SOA2 Service IDs** (`wordlists/soa2_service_ids.txt`) 
- 160 service identifiers
- Confirmed working IDs included
- Travel industry focused

#### 3. **API Endpoints** (`wordlists/api_endpoints.txt`)
- RESTful API patterns
- GraphQL endpoints  
- Common API paths

#### 4. **Dev Interfaces** (`wordlists/dev_interfaces.txt`)
- Development environments
- Debug interfaces
- Testing endpoints

---

## 🚀 Zaawansowane Narzędzia

### Nuclei Integration

#### XSS Template Scanning
```bash
# Scan discovered targets
make nuclei-scan

# Custom templates
./tools/nuclei-runner --templates discovery

# Specific targets
./tools/nuclei-runner -t targets.txt --templates xss
```

#### Template Categories
- **XSS Templates**: Reflected, stored, DOM-based
- **Discovery Templates**: Technology detection
- **Exposure Templates**: Sensitive file disclosure
- **Misconfiguration**: Security misconfigurations

### Mass Validation

#### Endpoint Verification
```bash
# Validate all discovered targets
make mass-validate

# Custom endpoint file
./tools/mass-validator -f targets.txt -c 100

# Analysis only
./tools/mass-validator --analyze-only results.json
```

#### Validation Features
- **Technology Detection**: Framework identification
- **Security Headers**: Missing/weak headers
- **Performance Metrics**: Response time analysis
- **Content Analysis**: Title extraction, interesting paths

### Real-time Monitoring

#### Continuous Monitoring
```bash
# Start monitoring (continuous)
make monitor

# Single cycle
make monitor-once

# Custom configuration
./tools/realtime-monitor -c monitoring_config.json --interval 1800
```

#### Monitoring Features
- **SQLite Database**: Target tracking
- **Automated Scanning**: Periodic vulnerability checks
- **Notification Support**: Webhook integration
- **Statistics**: Comprehensive monitoring stats

---

## 🔄 Pipeline'y Automatyzacji

### Full Pipeline
```bash
# Complete automation pipeline
make full-pipeline
```

**Execution Steps:**
1. **Target Discovery** → Shodan + Fofa search
2. **Mass Validation** → Endpoint verification  
3. **Nuclei Scanning** → Vulnerability detection
4. **Report Generation** → Comprehensive results

### Quick Pipeline
```bash
# Fast discovery and validation
make quick-pipeline
```

**Execution Steps:**
1. **SOA2 Discovery** → Specialized target hunting
2. **Mass Validation** → Quick endpoint check

### Custom Workflows

#### Discovery → Hunting → Scanning
```bash
# Step 1: Discover targets
make target-hunt-soa2

# Step 2: Hunt endpoints  
make wordlist-soa2 DOMAIN=discovered_domain.com

# Step 3: Validate findings
make mass-validate

# Step 4: Security scan
make nuclei-scan
```

---

## 🔑 Konfiguracja API

### Supported APIs

#### Fofa API
- **Purpose**: Chinese cybersecurity search engine
- **Strengths**: Chinese infrastructure, travel sites
- **Rate Limits**: Handled automatically
- **Authentication**: Email + API Key

#### Shodan API  
- **Purpose**: Internet-connected device search
- **Strengths**: Global coverage, device details
- **Rate Limits**: 1 request/second (free tier)
- **Authentication**: API Key only

### Configuration Files

#### Global Config (`~/.env_secrets`)
```bash
export FOFA_EMAIL="email@example.com"
export FOFA_KEY="fofa-api-key"
export SHODAN_API_KEY="shodan-api-key"
```

#### Project Config (`config/`)
```bash
# Create config files
echo "email@example.com" > config/fofa_email.txt
echo "fofa-api-key" > config/fofa_api_key.txt
echo "shodan-api-key" > config/shodan_api_key.txt
```

---

## 📚 Wordlisty i Payloady

### Specialized Wordlists

#### SOA2 Infrastructure
- **Source**: Real Ctrip.com reconnaissance
- **Patterns**: `/restapi/soa2/{service_id}/{endpoint}`
- **Validation**: Confirmed working endpoints included

#### Travel Industry Focus
- **Domains**: Ctrip, Trip.com, Qunar, Fliggy
- **Endpoints**: Booking, payment, user management
- **Languages**: English + Chinese support

### Payload Categories

#### XSS Payloads (`xss_vibes/data/`)
1. **Basic XSS** - Simple script injections
2. **Advanced Evasion** - WAF bypass techniques  
3. **DOM Manipulation** - Client-side attacks
4. **Blind XSS** - Out-of-band detection
5. **Encoded Payloads** - Various encoding schemes
6. **Polyglot Payloads** - Multi-context exploitation

---

## 💡 Przykłady Użycia

### Scenario 1: Travel Industry Research

```bash
# Discover Chinese travel platforms
make target-hunt-soa2

# Hunt SOA2 endpoints on discovered targets  
make wordlist-soa2 DOMAIN=app.ctrip.com

# Validate and scan
make mass-validate
make nuclei-scan
```

### Scenario 2: Admin Panel Discovery

```bash
# Search for admin interfaces
make fofa QUERY='title="admin"'
make shodan QUERY='http.title:"login"'

# Validate discovered panels
./tools/mass-validator -f fofa_results.json

# Technology analysis
./tools/mass-validator --analyze-only validation_results.json
```

### Scenario 3: Continuous Monitoring

```bash
# Setup monitoring configuration
cat > monitoring_config.json << EOF
{
  "fofa_queries": ["title=\"admin\"", "body=\"soa2\""],
  "shodan_queries": ["http.title:login"],
  "scan_interval": 3600,
  "max_targets_per_run": 50
}
EOF

# Start monitoring
./tools/realtime-monitor -c monitoring_config.json
```

### Scenario 4: Custom Development

```bash
# Hunt development interfaces
make dev-hunt DOMAIN=dev.example.com

# API discovery
make api-hunt DOMAIN=api.example.com

# Combined approach
make ultimate-hunt DOMAIN=example.com
```

---

## 🔧 Rozwiązywanie Problemów

### Częste Problemy

#### 1. **API Rate Limiting**
```bash
# Problem: Too many requests
# Solution: Increase delays
./tools/fofa-searcher -q "query" --delay 3

# Or reduce concurrency
./tools/mass-validator -c 20
```

#### 2. **Missing Dependencies**
```bash
# Install all dependencies
make deps

# Install crawler-specific deps
pip install -r requirements_crawler.txt
```

#### 3. **Permission Errors**
```bash
# Fix tool permissions
make crawler

# Manual fix
chmod +x tools/*
```

#### 4. **Large Result Sets**
```bash
# Limit results
./tools/fofa-searcher -q "query" --max-results 100

# Process in batches
./tools/mass-validator -c 50 --timeout 15
```

### Debug Mode

#### Verbose Logging
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
./tools/nuclei-runner --verbose

# Check logs
tail -f nuclei_runner.log
tail -f mass_validator.log
tail -f monitoring.log
```

### Performance Optimization

#### System Tuning
```bash
# Increase file descriptors
ulimit -n 65536

# Optimize for mass validation
./tools/mass-validator -c 100 --timeout 5

# Memory management
export PYTHONUNBUFFERED=1
```

---

## 📊 Output Formats

### Result Files

#### Discovery Results
- `simple_target_hunt.json` - Combined discovery results
- `fofa_results.json` - Fofa search results  
- `shodan_results.json` - Shodan search results

#### Validation Results
- `validation_results.json` - Mass validation output
- `nuclei_results.json` - Security scan results
- `monitoring.db` - SQLite monitoring database

#### Log Files
- `mass_validator.log` - Validation logs
- `nuclei_runner.log` - Scanning logs  
- `monitoring.log` - Real-time monitoring logs

### Result Analysis

#### JSON Structure Example
```json
{
  "target": "https://example.com",
  "status": "accessible",
  "status_code": 200,
  "response_time": 245.67,
  "technologies": ["nginx", "react"],
  "security_headers": {
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'"
  },
  "interesting_paths": ["/api/v1/", "/admin/"]
}
```

---

## 🎉 Podsumowanie

**XSS Vibes V2** zapewnia kompletną platformę do:

✅ **Automated Target Discovery** - Multi-source intelligence gathering  
✅ **Specialized Hunting** - SOA2 + travel industry focus  
✅ **Mass Validation** - Bulk endpoint verification  
✅ **Security Scanning** - Nuclei template integration  
✅ **Real-time Monitoring** - Continuous surveillance  
✅ **Full Automation** - Pipeline-driven workflows

### Quick Start Commands

```bash
# Setup
make install

# Discovery
make target-hunt-soa2

# Validation  
make mass-validate

# Scanning
make nuclei-scan

# Full pipeline
make full-pipeline
```

---

## 📞 Support & Kontakt

- **GitHub**: [XSS-VibesV2](https://github.com/jarek-bir/XSS-VibesV2)
- **Documentation**: `docs/` directory
- **Issues**: GitHub Issues
- **Updates**: `make update-payloads`

---

*XSS Vibes V2 - Advanced XSS Discovery Platform*  
*Built for Security Researchers by Security Researchers* 🔥
