# XSS Vibes V2 - Quick Start Guide

## 🚀 Szybki Start

### 1. Instalacja
```bash
git clone https://github.com/jarek-bir/XSS-VibesV2.git
cd XSS-VibesV2
make install
```

### 2. Konfiguracja API
```bash
# Dodaj klucze API do ~/.env_secrets
cat > ~/.env_secrets << EOF
export FOFA_EMAIL="your-email@example.com"
export FOFA_KEY="your-fofa-api-key"
export SHODAN_API_KEY="your-shodan-api-key"
EOF
```

### 3. Podstawowe Komendy

#### Discovery & Hunting
```bash
# SOA2 target discovery (travel industry)
make target-hunt-soa2

# Admin panel search
make fofa QUERY='title="admin"'

# Login page discovery  
make shodan QUERY='http.title:"login"'

# Wordlist hunting na konkretnym domain
make wordlist-soa2 DOMAIN=app.ctrip.com
```

#### Validation & Scanning
```bash
# Mass validation discovered endpoints
make mass-validate

# Nuclei XSS scanning
make nuclei-scan

# Real-time monitoring
make monitor-once
```

#### Full Automation
```bash
# Complete pipeline
make full-pipeline

# Quick pipeline
make quick-pipeline
```

## 📊 Dostępne Narzędzia

### Discovery Tools
- `tools/fofa-searcher` - Fofa API integration
- `tools/shodan-searcher` - Shodan API integration  
- `tools/simple-target-hunter` - Combined discovery

### Hunting Tools
- `tools/wordlist-hunter` - Wordlist-based hunting
- `tools/ultimate-hunter` - Advanced reconnaissance
- `tools/ctrip-hunter` - SOA2 specialized hunting

### Advanced Tools
- `tools/nuclei-runner` - Nuclei template integration
- `tools/mass-validator` - Bulk endpoint validation
- `tools/realtime-monitor` - Continuous monitoring

## 🎯 Specialized Features

### SOA2 Hunting (Travel Industry)
- Based on real Ctrip.com patterns
- 160+ service IDs, 115+ endpoints
- Travel-specific queries and wordlists

### Multi-Source Discovery  
- Fofa + Shodan integration
- Chinese + international coverage
- Automated rate limiting

### Mass Validation
- Technology detection
- Security headers analysis
- Performance metrics
- Content analysis

## 📋 Output Files

- `simple_target_hunt.json` - Discovery results
- `validation_results.json` - Validation output
- `nuclei_results.json` - Security scan results
- `monitoring.db` - Real-time monitoring data

## 🔧 Makefile Commands

```bash
make help                    # Show all commands
make target-hunt-soa2       # SOA2 discovery
make mass-validate          # Validate endpoints
make nuclei-scan           # Security scanning
make monitor               # Real-time monitoring
make full-pipeline         # Complete automation
```

## 💡 Pro Tips

1. **Start with discovery**: `make target-hunt-soa2`
2. **Validate before scanning**: `make mass-validate`  
3. **Use monitoring for continuous discovery**: `make monitor`
4. **Check logs**: `tail -f *.log`
5. **Customize wordlists**: Edit `wordlists/*.txt`

---

*Ready to hunt? Start with `make target-hunt-soa2` 🎯*
