#!/usr/bin/env python3
"""
XSS Vibes - Path Updater
Aktualizuje ścieżki w kodzie po reorganizacji projektu
"""
import os
import re
from pathlib import Path


class PathUpdater:
    def __init__(self):
        self.project_root = Path("/home/jarek/xss_vibes")
        self.path_mappings = {
            "tools/analysis/ai_context_extractor.py": "tools/analysis/ai_context_extractor.py",
            "tools/analysis/extract_github_payloads.py": "tools/analysis/extract_github_payloads.py",
            "tools/integration/integrate_github_payloads.py": "tools/integration/integrate_github_payloads.py",
            "scripts/report_gen.py": "scripts/report_gen.py",  # Pozostaje w scripts/
        }

    def update_imports_in_file(self, file_path):
        """Aktualizuje importy w pliku"""
        try:
            with open(file_path, "r") as f:
                content = f.read()

            original_content = content

            # Aktualizuj ścieżki w importach
            for old_path, new_path in self.path_mappings.items():
                old_import = old_path.replace(".py", "").replace("/", ".")
                new_import = new_path.replace(".py", "").replace("/", ".")

                # Pattern dla różnych typów importów
                patterns = [
                    rf"from {re.escape(old_import)} import",
                    rf"import {re.escape(old_import)}",
                    rf'from .{re.escape(old_import.split(".")[-1])} import',
                    rf'import .{re.escape(old_import.split(".")[-1])}',
                ]

                for pattern in patterns:
                    content = re.sub(
                        pattern, pattern.replace(old_import, new_import), content
                    )

            # Aktualizuj ścieżki plików w stringach
            for old_path, new_path in self.path_mappings.items():
                content = content.replace(f'"{old_path}"', f'"{new_path}"')
                content = content.replace(f"'{old_path}'", f"'{new_path}'")

            if content != original_content:
                with open(file_path, "w") as f:
                    f.write(content)
                print(f"✅ Updated: {file_path}")
                return True

        except Exception as e:
            print(f"❌ Error updating {file_path}: {e}")

        return False

    def update_documentation(self):
        """Aktualizuje dokumentację z nowymi ścieżkami"""
        docs = ["AI_TOOLS_DOCUMENTATION.md", "USAGE_GUIDE.md", "README.md"]

        for doc in docs:
            doc_path = self.project_root / doc
            if doc_path.exists():
                self.update_imports_in_file(doc_path)

    def update_all_python_files(self):
        """Aktualizuje wszystkie pliki Python"""
        updated_count = 0

        for py_file in self.project_root.rglob("*.py"):
            if self.update_imports_in_file(py_file):
                updated_count += 1

        return updated_count

    def create_path_aliases(self):
        """Tworzy aliasy dla nowych ścieżek"""
        aliases_content = """#!/bin/bash
# XSS Vibes - Path Aliases (Post-Cleanup)

# AI Tools
alias ai-context="python3 tools/analysis/ai_context_extractor.py"
alias ai-domfuzz="python3 -m xss_vibes.ai_domfuzz"
alias ai-report="python3 scripts/report_gen.py"

# GitHub Analysis
alias github-extract="python3 tools/analysis/extract_github_payloads.py"
alias github-integrate="python3 tools/integration/integrate_github_payloads.py"

# Automation
alias xss-ultimate="bash tools/automation/ultimate_tester.sh"
alias xss-robust="bash tools/automation/robust_oneliners.sh"
alias xss-god="bash tools/automation/god_tier_tester.sh"

# Analysis Results
alias show-github="ls -la analysis_results/github/"
alias show-ai="ls -la analysis_results/ai_tools/"
alias show-reports="ls -la analysis_results/reports/"

echo "🔥 XSS Vibes aliases loaded! Use 'ai-context', 'ai-domfuzz', 'ai-report' etc."
"""

        aliases_file = self.project_root / "tools" / "aliases.sh"
        with open(aliases_file, "w") as f:
            f.write(aliases_content)

        print(f"✅ Created aliases: {aliases_file}")

    def run_update(self):
        """Wykonuje pełną aktualizację ścieżek"""
        print("🔄 XSS Vibes - Path Update Starting...")
        print("=" * 50)

        # Aktualizuj pliki Python
        updated = self.update_all_python_files()
        print(f"📝 Updated {updated} Python files")

        # Aktualizuj dokumentację
        self.update_documentation()
        print("📚 Updated documentation")

        # Utwórz aliasy
        self.create_path_aliases()

        print()
        print("✅ Path update complete!")
        print("💡 Source new aliases: source tools/aliases.sh")
        print("🚀 All paths updated for new project structure!")


if __name__ == "__main__":
    updater = PathUpdater()
    updater.run_update()
