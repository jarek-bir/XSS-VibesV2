# Makefile for XSS Vibes - Cross-platform build automation

# Variables
PYTHON := python3
PIP := pip3
BINARY_NAME := xss-vibes
VENV_DIR := venv
BUILD_DIR := dist
SOURCE_DIR := .

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: help install install-dev build build-all clean test lint format setup-venv binary install-binary legacy modern

# Default target
help:
	@echo "$(BLUE)XSS Vibes Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@echo "  $(GREEN)install$(NC)         - Install package dependencies"
	@echo "  $(GREEN)install-dev$(NC)     - Install with development dependencies"
	@echo "  $(GREEN)install-build$(NC)   - Install with build dependencies"
	@echo "  $(GREEN)setup-venv$(NC)      - Create virtual environment"
	@echo "  $(GREEN)binary$(NC)          - Build binary executable (modern version)"
	@echo "  $(GREEN)build-all$(NC)       - Build all binary variants"
	@echo "  $(GREEN)install-binary$(NC)  - Install binary to system"
	@echo "  $(GREEN)test$(NC)            - Run tests"
	@echo "  $(GREEN)lint$(NC)            - Run code linting"
	@echo "  $(GREEN)format$(NC)          - Format code with black"
	@echo "  $(GREEN)clean$(NC)           - Clean build artifacts"
	@echo "  $(GREEN)package$(NC)         - Create distribution packages"
	@echo "  $(GREEN)legacy$(NC)          - Run legacy version (for comparison)"
	@echo "  $(GREEN)modern$(NC)          - Run modern version"
	@echo ""
	@echo "$(YELLOW)Quick start:$(NC)"
	@echo "  make install-build && make binary"

# Setup environment
setup:
	@echo "📦 Setting up XSS Vibes modern environment..."
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

# Install as package
install:
	@echo "📦 Installing XSS Vibes as package..."
	pip install .
	@echo "✅ Installed! Use: xss-vibes --help"

# Development installation
dev:
	@echo "🛠️ Installing in development mode..."
	pip install -e .[dev]
	@echo "✅ Development environment ready"

# Test installation
test:
	@echo "🧪 Testing modern XSS Vibes..."
	python test_modern.py

# Compare versions
compare:
	@echo "🔍 Comparing legacy vs modern versions..."
	python compare_versions.py

# Run legacy version example
legacy:
	@echo "🕰️ Running legacy version..."
	@if [ -f "main.py" ]; then \
		echo "Example: python main.py -u 'http://testphp.vulnweb.com/listproducts.php?cat=1'"; \
	else \
		echo "❌ Legacy main.py not found"; \
	fi

# Run modern version example
modern:
	@echo "🚀 Running modern version..."
	@echo "Examples:"
	@echo "  python main_modern.py --help"
	@echo "  python main_modern.py -u 'http://testphp.vulnweb.com/listproducts.php?cat=1'"
	@echo "  python main_modern.py -u 'http://testphp.vulnweb.com/listproducts.php?cat=1' --async"

# Clean temporary files
clean:
	@echo "🧹 Cleaning temporary files..."
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .pytest_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	@echo "✅ Cleaned"

# Lint code
lint:
	@echo "🔍 Linting code..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 *.py --max-line-length=100 --ignore=E203,W503; \
	else \
		echo "Install flake8 for linting: pip install flake8"; \
	fi

# Format code
format:
	@echo "🎨 Formatting code..."
	@if command -v black >/dev/null 2>&1; then \
		black *.py; \
	else \
		echo "Install black for formatting: pip install black"; \
	fi

# Type check
typecheck:
	@echo "🔎 Type checking..."
	@if command -v mypy >/dev/null 2>&1; then \
		mypy *.py --ignore-missing-imports; \
	else \
		echo "Install mypy for type checking: pip install mypy"; \
	fi

# Full quality check
quality: lint format typecheck
	@echo "✅ Code quality checks completed"

# Create example config
config:
	@echo "⚙️ Creating example configuration..."
	@cat > config.json << 'EOF'
	{
	  "max_threads": 5,
	  "default_timeout": 10,
	  "verify_ssl": false,
	  "crawl_depth": 4,
	  "default_headers": {
	    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
	  }
	}
	EOF
	@echo "✅ Created config.json"

# Show status
status:
	@echo "📊 XSS Vibes Status"
	@echo "=================="
	@echo "Python version: $$(python --version)"
	@echo "Files present:"
	@ls -la *.py | wc -l | xargs echo "  Python files:"

# Binary building targets
install-build:
	@echo "$(BLUE)Installing build dependencies...$(NC)"
	pip install pyinstaller setuptools wheel

binary:
	@echo "$(BLUE)Building binary executable...$(NC)"
	python build.py --modern-only
	@if [ -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "$(GREEN)✅ Binary built successfully: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"; \
		ls -lh $(BUILD_DIR)/$(BINARY_NAME); \
	else \
		echo "$(RED)❌ Binary build failed$(NC)"; \
		exit 1; \
	fi

build-all:
	@echo "$(BLUE)Building all binary variants...$(NC)"
	python build.py --all

# System installation
install-binary: binary
	@echo "$(BLUE)Installing binary to system...$(NC)"
	python build.py --install-scripts
	./install.sh

# Package creation
package:
	@echo "$(BLUE)Creating distribution packages...$(NC)"
	python setup.py sdist bdist_wheel
	@echo "$(GREEN)Packages created in dist/$(NC)"

# Check system requirements
check-deps:
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)Python 3 not found$(NC)"; exit 1; }
	@python3 -c "import sys; assert sys.version_info >= (3, 8)" || { echo "$(RED)Python 3.8+ required$(NC)"; exit 1; }
	@echo "$(GREEN)Dependencies OK$(NC)"

# Production build workflow
prod-build: check-deps install-build binary
	@echo "$(GREEN)Production binary ready! File: dist/$(BINARY_NAME)$(NC)"
	@if [ -f "payloads.json" ]; then echo "  ✅ payloads.json"; else echo "  ❌ payloads.json"; fi
	@if [ -f "waf_list.txt" ]; then echo "  ✅ waf_list.txt"; else echo "  ❌ waf_list.txt"; fi
	@if [ -f "config.json" ]; then echo "  ✅ config.json"; else echo "  ❌ config.json (run 'make config')"; fi

# Run full test suite
test-full: test compare
	@echo "🎉 All tests completed!"

# Quick demo
demo:
	@echo "🎭 XSS Vibes Demo"
	@echo "================"
	@echo "1. Testing basic functionality..."
	@python test_modern.py
	@echo ""
	@echo "2. Showing help..."
	@python main_modern.py --help | head -20
	@echo ""
	@echo "3. Demo completed! Try:"
	@echo "   python main_modern.py -u 'http://testphp.vulnweb.com/listproducts.php?cat=1'"
