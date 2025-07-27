# Building XSS Vibes Binary 🔧

Ten przewodnik pokazuje jak zbudować wykonywalną binarkę z XSS Vibes.

## 🛠️ Szybki Start

### 1. Przygotowanie środowiska
```bash
# Zainstaluj zależności do buildowania
make install-build

# Lub ręcznie:
pip install pyinstaller
```

### 2. Budowanie binarki
```bash
# Zbuduj nowoczesną wersję
make binary

# Lub użyj skryptu bezpośrednio:
python build.py --modern-only
```

### 3. Instalacja w systemie
```bash
# Zainstaluj binarkę systemowo
make install-binary

# Lub ręcznie:
./install.sh
```

## 📋 Opcje Buildowania

### Podstawowe komendy
```bash
# Tylko nowoczesna wersja
python build.py --modern-only

# Wszystkie warianty (jeśli dostępne)
python build.py --all

# Stwórz skrypty instalacyjne
python build.py --install-scripts

# Wyczyść artefakty
python build.py --clean
```

### Użycie Makefile
```bash
# Sprawdź zależności
make check-deps

# Zainstaluj zależności build
make install-build

# Zbuduj binarkę
make binary

# Zbuduj wszystkie warianty
make build-all

# Zainstaluj w systemie
make install-binary

# Kompletny workflow produkcyjny
make prod-build
```

## 🎯 Warianty Binarek

### 1. xss-vibes (nowoczesna wersja)
- Pełna funkcjonalność async/await
- Wsparcie dla wszystkich nowych funkcji
- Rekomendowana wersja

### 2. xss-vibes-legacy (jeśli dostępna)
- Kompatybilność wsteczna
- Stara implementacja

## 📦 Zawartość Binarki

Binarka zawiera:
- Wszystkie moduły Python
- Pliki konfiguracyjne (payloads.json, waf_list.txt)
- Dokumentację
- Zależności (requests, aiohttp, colorama, wafw00f)

## 🗂️ Struktura po Buildowaniu

```
xss_vibes/
├── dist/
│   ├── xss-vibes              # Główna binarka
│   └── xss-vibes-legacy       # Wersja legacy (opcjonalnie)
├── build/                     # Tymczasowe pliki build
├── install.sh                 # Instalator dla Linux/macOS
├── install.bat                # Instalator dla Windows
└── xss-vibes.spec            # PyInstaller spec (opcjonalnie)
```

## 🖥️ Instalacja Systemowa

### Linux/macOS
```bash
# Automatyczna instalacja
./install.sh

# Ręczna instalacja
sudo cp dist/xss-vibes /usr/local/bin/
sudo chmod +x /usr/local/bin/xss-vibes

# Stwórz katalog konfiguracji
mkdir -p ~/.xss-vibes
cp payloads.json ~/.xss-vibes/
cp waf_list.txt ~/.xss-vibes/
```

### Windows
```cmd
REM Uruchom jako administrator
install.bat

REM Lub ręcznie:
copy dist\xss-vibes.exe "C:\Program Files\XSSVibes\"
```

## ✅ Testowanie Binarki

```bash
# Sprawdź czy binarka działa
./dist/xss-vibes --help

# Przetestuj podstawową funkcjonalność
./dist/xss-vibes -u "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Sprawdź wersję zainstalowaną systemowo
xss-vibes --help
```

## 🔧 Rozwiązywanie problemów

### Problem: "PyInstaller not found"
```bash
pip install pyinstaller
```

### Problem: "Permission denied"
```bash
chmod +x dist/xss-vibes
```

### Problem: Brak payloads.json
```bash
# Upewnij się że pliki konfiguracyjne istnieją
ls -la payloads.json waf_list.txt
```

### Problem: Import errors w binarce
```bash
# Przebuduj z dodatkowymi hidden-imports
python build.py --spec  # Stwórz .spec file
# Edytuj .spec i dodaj brakujące moduły
pyinstaller xss-vibes.spec
```

## 📊 Rozmiar Binarki

- **Nowoczesna wersja**: ~15-20 MB
- **Skompresowana**: ~8-12 MB (z UPX)
- **Zawiera**: Python runtime + wszystkie zależności

## 🚀 Optymalizacja

### Zmniejszenie rozmiaru
```bash
# Użyj UPX do kompresji (jeśli dostępne)
upx --best dist/xss-vibes

# Stwórz wersję --onedir zamiast --onefile (szybsza)
# Edytuj build.py i zmień onefile=False
```

### Optymalizacja wydajności
- Binarka może być wolniejsza niż skrypt Python
- Async wersja nadal działa efektywnie
- Cache startowy może potrwać 1-2 sekundy

## 🎉 Gratulacje!

Po pomyślnym buildowaniu masz:
1. ✅ Wykonywalną binarkę w `dist/xss-vibes`
2. ✅ Skrypty instalacyjne
3. ✅ Gotową dystrybucję

Możesz teraz:
- Dystrybuować binarkę bez wymagania Python
- Zainstalować jako systemowe narzędzie
- Uruchamiać na systemach bez Pythona
- Używać w skryptach i automatyzacji

---

**Przykład użycia zainstalowanej binarki:**
```bash
xss-vibes -u "http://example.com/?id=1" --async --json-output results.json
```
