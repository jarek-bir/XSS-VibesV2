# 📁 XSS Vibes - Pliki testowe

Przygotowałem dla Ciebie kilka plików z testowymi URLami:

## 📋 Dostępne pliki:

### 🔍 `quick-test.txt` (5 URLi)
**Najlepsze do szybkiego testowania podstawowych funkcji**
```bash
xss-vibes scan -l quick-test.txt --dry-run
```

### 🛡️ `safe-test-urls.txt` (18 URLi) 
**Bezpieczne URLe do testowania funkcjonalności bez ryzyka**
```bash
xss-vibes scan -l safe-test-urls.txt --dry-run --threads 3
```

### ⚡ `xss-test-urls.txt` (22 URLi)
**Specjalne URLe z payloadami XSS do testowania wykrywania**
```bash
xss-vibes scan -l xss-test-urls.txt --enhanced-payloads --dry-run
```

### 🎯 `test-urls.txt` (26 URLi)
**Pełny zestaw różnorodnych URLi, including DVWA-style vulnerable apps**
```bash
xss-vibes scan -l test-urls.txt --waf-mode --stealth --dry-run
```

## 🚀 Przykłady użycia:

### Szybki test:
```bash
xss-vibes scan -l quick-test.txt --dry-run
```

### Test z zaawansowanymi opcjami:
```bash
xss-vibes scan -l safe-test-urls.txt --enhanced-payloads --threads 2 --timeout 15 --dry-run
```

### Test z evasion:
```bash
xss-vibes scan -l xss-test-urls.txt --waf-mode --encoding-level 2 --stealth --dry-run
```

### Test z mutation:
```bash
xss-vibes scan -l quick-test.txt --mutation --mutation-generations 3 --dry-run
```

### Prawdziwy scan (usuń --dry-run):
```bash
xss-vibes scan -l quick-test.txt --enhanced-payloads -o wyniki.json
```

## 💡 Porady:
- Zawsze używaj `--dry-run` najpierw, żeby sprawdzić konfigurację
- `httpbin.org` i `postman-echo.com` to bezpieczne serwisy do testowania
- URLe z `demo.testfire.net` to intentionally vulnerable demo aplikacje
- Użyj `--threads 2-3` dla szybszego skanowania
- `--enhanced-payloads` daje dostęp do 2926 dodatkowych payloadów
