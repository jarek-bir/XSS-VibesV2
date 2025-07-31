# XSS Vibes V2 - Enhanced Security Testing Framework
# Makefile for easy project management

.PHONY: help install test run clean deps lint format check-security update-payloads build package docs crawler hunt

# Default target
help:
	@echo "🔥 XSS Vibes V2 - Available Commands:"
	@echo ""
	@echo "📦 Installation & Setup:"
	@echo "  make install          - Install all dependencies"
	@echo "  make deps            - Install Python dependencies only"
	@echo "  make build           - Build the package"
	@echo "  make package         - Create distribution package"
	@echo ""
	@echo "🚀 Running & Testing:"
	@echo "  make run             - Run XSS scanner with default settings"
	@echo "  make test            - Run test suite"
	@echo "  make check           - Run all quality checks"
	@echo ""
	@echo "🕷️ Advanced Crawler (Osmedeus-style):"
	@echo "  make crawler         - Setup and prepare crawler tools"
	@echo "  make hunt DOMAIN=x   - Quick domain reconnaissance"
	@echo "  make dev-hunt DOMAIN=x - Hunt development interfaces"
	@echo "  make api-hunt DOMAIN=x - Hunt API endpoints"
	@echo "  make ultimate-hunt DOMAIN=x - Comprehensive reconnaissance"
	@echo "  make ultimate-hunt-deep DOMAIN=x - Deep comprehensive hunt"
	@echo "  make soa2-hunt       - Specialized SOA2 endpoint hunt (Ctrip patterns)"
	@echo "  make cross-domain-hunt - Cross-domain SOA2 hunt"
	@echo "  make wordlist-hunt DOMAIN=x [TYPE=all] - Wordlist-based hunting"
	@echo "  make wordlist-soa2 DOMAIN=x - SOA2 wordlist hunt"
	@echo "  make fofa QUERY=x    - Fofa search reconnaissance"
	@echo "  make shodan QUERY=x  - Shodan search reconnaissance"
	@echo "  make target-hunt     - Combined Shodan+Fofa target discovery"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make lint            - Run code linting"
	@echo "  make format          - Format code"
	@echo "  make clean           - Clean temporary files"
	@echo ""
	@echo "📚 Documentation & Updates:"
	@echo "  make docs            - Generate documentation"
	@echo "  make update-payloads - Update payload database"
	@echo "  make check-security  - Security audit"
	@echo ""

# Installation and dependencies
install: deps
	@echo "🔧 Installing XSS Vibes V2..."
	pip install -e .
	@echo "✅ Installation complete!"

deps:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	pip install -r requirements_crawler.txt
	@echo "✅ Dependencies installed!"

# Advanced Crawler commands
crawler:
	@echo "🕷️ Setting up Advanced Crawler..."
	chmod +x tools/xss-crawler
	chmod +x tools/xss-hunt
	chmod +x tools/dev-hunter
	chmod +x tools/api-hunter
	chmod +x tools/nuclei-runner
	chmod +x tools/realtime-monitor
	chmod +x tools/mass-validator
	@echo "✅ Crawler tools ready!"
	@echo ""
	@echo "Usage examples:"
	@echo "  make hunt DOMAIN=example.com"
	@echo "  make dev-hunt DOMAIN=example.com"
	@echo "  make api-hunt DOMAIN=example.com"
	@echo "  make fofa QUERY='title=\"admin\"'"
	@echo "  make shodan QUERY='http.title:login'"
	@echo "  make nuclei-scan"
	@echo "  make mass-validate"

hunt:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make hunt DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "🎯 Starting reconnaissance for $(DOMAIN)..."
	./tools/xss-hunt $(DOMAIN)

dev-hunt:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make dev-hunt DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "🔍 Starting development interface hunt for $(DOMAIN)..."
	./tools/dev-hunter $(DOMAIN)

api-hunt:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make api-hunt DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "🔍 Starting API endpoint hunt for $(DOMAIN)..."
	./tools/api-hunter $(DOMAIN)

ultimate-hunt:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make ultimate-hunt DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "🔥 Starting ultimate hunt for $(DOMAIN)..."
	./tools/ultimate-hunter $(DOMAIN)

ultimate-hunt-deep:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make ultimate-hunt-deep DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "🔥 Starting ultimate DEEP hunt for $(DOMAIN)..."
	./tools/ultimate-hunter $(DOMAIN) --deep

soa2-hunt:
	@echo "🎯 Starting specialized SOA2 hunt on Ctrip patterns..."
	./tools/ctrip-hunter

cross-domain-hunt:
	@echo "🌐 Starting cross-domain SOA2 hunt..."
	./tools/cross-domain-soa2-hunter

wordlist-hunt:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make wordlist-hunt DOMAIN=example.com [TYPE=soa2|api|dev|all]"; \
		exit 1; \
	fi
	@echo "📚 Starting wordlist hunt for $(DOMAIN)..."
	./tools/wordlist-hunter $(DOMAIN) -t $(shell echo $(TYPE) | sed 's/^$$/all/')

wordlist-soa2:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "❌ Error: DOMAIN parameter required"; \
		echo "Usage: make wordlist-soa2 DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "📚 Starting SOA2 wordlist hunt for $(DOMAIN)..."
	./tools/wordlist-hunter $(DOMAIN) -t soa2

fofa:
	@if [ -z "$(QUERY)" ]; then \
		echo "❌ Error: QUERY parameter required"; \
		echo "Usage: make fofa QUERY='title=\"admin\"'"; \
		exit 1; \
	fi
	@echo "🔍 Starting Fofa search: $(QUERY)"
	@if [ -f ~/.env_secrets ]; then \
		. ~/.env_secrets && ./tools/fofa-searcher -q "$(QUERY)" --email "$$FOFA_EMAIL" --key "$$FOFA_KEY"; \
	else \
		./tools/fofa-searcher -q "$(QUERY)"; \
	fi

shodan:
	@if [ -z "$(QUERY)" ]; then \
		echo "❌ Error: QUERY parameter required"; \
		echo "Usage: make shodan QUERY='http.title:login'"; \
		exit 1; \
	fi
	@echo "🌐 Starting Shodan search: $(QUERY)"
	@if [ -f ~/.env_secrets ]; then \
		. ~/.env_secrets && ./tools/shodan-searcher -q "$(QUERY)" --key "$$SHODAN_API_KEY"; \
	else \
		./tools/shodan-searcher -q "$(QUERY)"; \
	fi

target-hunt:
	@echo "🎯 Starting combined target discovery..."
	@if [ -f ~/.env_secrets ]; then \
		echo "📊 Loading API keys from ~/.env_secrets"; \
		. ~/.env_secrets && ./tools/simple-target-hunter --fofa-email "$$FOFA_EMAIL" --fofa-key "$$FOFA_KEY" --shodan-key "$$SHODAN_API_KEY"; \
	else \
		echo "⚠️  No ~/.env_secrets found, using environment variables"; \
		./tools/simple-target-hunter --fofa-email "$(FOFA_EMAIL)" --fofa-key "$(FOFA_KEY)" --shodan-key "$(SHODAN_KEY)"; \
	fi

target-hunt-soa2:
	@echo "🎯 Starting SOA2 target discovery..."
	@if [ -f ~/.env_secrets ]; then \
		echo "📊 Loading API keys from ~/.env_secrets"; \
		. ~/.env_secrets && ./tools/simple-target-hunter -s soa2_discovery --fofa-email "$$FOFA_EMAIL" --fofa-key "$$FOFA_KEY" --shodan-key "$$SHODAN_API_KEY"; \
	else \
		echo "⚠️  No ~/.env_secrets found, using environment variables"; \
		./tools/simple-target-hunter -s soa2_discovery --fofa-email "$(FOFA_EMAIL)" --fofa-key "$(FOFA_KEY)" --shodan-key "$(SHODAN_KEY)"; \
	fi

# Development and testing
run:
	@echo "🚀 Running XSS Vibes V2..."
	python -m xss_vibes

test:
	@echo "🧪 Running tests..."
	python -m pytest tests/ -v
	python test_modern.py
	python test_waf_payloads.py

check: lint test
	@echo "✅ All checks passed!"

lint:
	@echo "🔍 Running code analysis..."
	flake8 xss_vibes/ --max-line-length=120
	pylint xss_vibes/ --disable=C0114,C0115,C0116

format:
	@echo "🎨 Formatting code..."
	black xss_vibes/
	isort xss_vibes/

# Build and package
build:
	@echo "🏗️ Building package..."
	python setup.py build

package:
	@echo "📦 Creating distribution package..."
	python setup.py sdist bdist_wheel

# Documentation and updates
docs:
	@echo "📚 Generating documentation..."
	@echo "Available documentation:"
	@echo "  📖 README.md - Main documentation"
	@echo "  🔥 ADVANCED_FEATURES.md - Advanced features guide"
	@echo "  📋 docs/ADVANCED_XSS_CATEGORIES.md - Advanced XSS categories"
	@echo "  🔧 BUILD_GUIDE.md - Build instructions"

update-payloads:
	@echo "🔄 Updating payload database..."
	@python -c "\
from xss_vibes.payload_manager import PayloadManager; \
pm = PayloadManager(); \
pm.update_payloads(); \
print('✅ Payloads updated!')"

check-security:
	@echo "🔒 Running security audit..."
	pip-audit
	bandit -r xss_vibes/

# Cleanup
clean:
	@echo "🧹 Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .pytest_cache/
	@echo "✅ Cleanup complete!"

# Show crawler workspaces
workspaces:
	@echo "📁 Available workspaces:"
	@if [ -d "workspaces" ]; then \
		ls -la workspaces/; \
	else \
		echo "No workspaces found. Create one with 'make hunt' or 'make crawler'"; \
	fi

# Show latest scan results
results:
	@echo "📊 Latest scan results:"
	@if [ -d "workspaces" ]; then \
		latest=$$(ls -t workspaces/ | head -1); \
		if [ -n "$$latest" ]; then \
			echo "Latest workspace: $$latest"; \
			if [ -f "workspaces/$$latest/reports/summary.json" ]; then \
				echo "Summary:"; \
				cat "workspaces/$$latest/reports/summary.json" | python -m json.tool; \
			fi; \
		fi; \
	else \
		echo "No results found"; \
	fi

# Advanced Security Tools
nuclei-scan:
	@echo "🎯 Running nuclei scan on discovered targets..."
	./tools/nuclei-runner --templates xss

mass-validate:
	@echo "🔍 Mass validating discovered endpoints..."
	./tools/mass-validator

monitor:
	@echo "📡 Starting real-time monitoring pipeline..."
	@echo "⚠️  This will run continuously. Press Ctrl+C to stop."
	./tools/realtime-monitor

monitor-once:
	@echo "🔄 Running single monitoring cycle..."
	./tools/realtime-monitor --once

# Pipeline commands (full automation)
full-pipeline:
	@echo "🚀 Starting full XSS discovery pipeline..."
	@echo "📊 Step 1: Target discovery..."
	@if [ -f ~/.env_secrets ]; then \
		. ~/.env_secrets && ./tools/simple-target-hunter -s soa2_discovery --fofa-email "$$FOFA_EMAIL" --fofa-key "$$FOFA_KEY" --shodan-key "$$SHODAN_API_KEY"; \
	else \
		echo "⚠️  ~/.env_secrets not found - skipping discovery"; \
	fi
	@echo "📊 Step 2: Mass validation..."
	./tools/mass-validator
	@echo "📊 Step 3: Nuclei scan..."
	./tools/nuclei-runner --templates xss
	@echo "✅ Full pipeline complete!"

quick-pipeline:
	@echo "⚡ Quick XSS discovery pipeline..."
	make target-hunt-soa2
	make mass-validate
	@echo "✅ Quick pipeline complete!"
