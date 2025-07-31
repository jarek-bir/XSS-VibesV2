#!/usr/bin/env python3
"""
XSS Vibes - Project Cleanup & Organization Tool
Porządkuje strukturę projektu i optymalizuje pliki
"""
import os
import shutil
import json
from pathlib import Path
from datetime import datetime


class XSSVibesCleanup:
    def __init__(self):
        self.project_root = Path("/home/jarek/xss_vibes")
        self.cleanup_stats = {
            "files_moved": 0,
            "directories_created": 0,
            "files_removed": 0,
            "files_optimized": 0,
        }

    def create_directory_structure(self):
        """Tworzy optymalną strukturę katalogów"""
        directories = [
            "analysis_results/github",
            "analysis_results/ai_tools",
            "analysis_results/reports",
            "tools/integration",
            "tools/analysis",
            "tools/automation",
            "backup/configs",
            "backup/payloads",
            "temp/extraction",
            "docs/ai_tools",
            "docs/usage",
        ]

        for dir_path in directories:
            full_path = self.project_root / dir_path
            if not full_path.exists():
                full_path.mkdir(parents=True, exist_ok=True)
                self.cleanup_stats["directories_created"] += 1
                print(f"📁 Created: {dir_path}")

    def organize_analysis_files(self):
        """Organizuje pliki analizy"""
        analysis_dir = self.project_root / "analysis_results"

        # GitHub analysis files
        github_files = [
            "gist_analysis.json",
            "github_extracted_payloads.json",
            "github_fuzz_payloads.json",
            "github_integration_summary.json",
            "github_real_world_payloads.json",
            "github_targeted_payloads.json",
        ]

        github_dir = analysis_dir / "github"
        for file in github_files:
            source = analysis_dir / file
            if source.exists():
                shutil.move(str(source), str(github_dir / file))
                self.cleanup_stats["files_moved"] += 1
                print(f"📄 Moved: {file} -> github/")

        # AI tools results
        ai_files = [
            "ai_test_results.json",
            "demo_ai_results.json",
            "demo_complete_results.json",
            "demo_results.json",
        ]

        ai_dir = analysis_dir / "ai_tools"
        for file in ai_files:
            source = analysis_dir / file
            if source.exists():
                shutil.move(str(source), str(ai_dir / file))
                self.cleanup_stats["files_moved"] += 1
                print(f"📄 Moved: {file} -> ai_tools/")

    def organize_scripts(self):
        """Organizuje skrypty wg kategorii"""
        scripts_dir = self.project_root / "scripts"
        tools_dir = self.project_root / "tools"

        # Integration scripts
        integration_scripts = ["integrate_new_payloads.py", "oneliner_integration.py"]

        integration_dir = tools_dir / "integration"
        for script in integration_scripts:
            source = scripts_dir / script
            if source.exists():
                shutil.move(str(source), str(integration_dir / script))
                self.cleanup_stats["files_moved"] += 1
                print(f"🔧 Moved: {script} -> tools/integration/")

        # Analysis scripts
        analysis_scripts = [
            "ai_context_extractor.py",
            "extract_github_payloads.py",
            "contextual_generator.py",
            "smart_payload_selector.py",
        ]

        analysis_dir = tools_dir / "analysis"
        for script in analysis_scripts:
            source = scripts_dir / script
            if source.exists():
                shutil.move(str(source), str(analysis_dir / script))
                self.cleanup_stats["files_moved"] += 1
                print(f"🔍 Moved: {script} -> tools/analysis/")

        # Automation scripts
        automation_scripts = [
            "ultimate_tester.sh",
            "robust_oneliners.sh",
            "god_tier_tester.sh",
            "hackvault_polyglot_tester.sh",
            "quick_multi_test.sh",
            "xss_hunting_automation.py",
            "multi_vuln_tester.py",
        ]

        automation_dir = tools_dir / "automation"
        for script in automation_scripts:
            source = scripts_dir / script
            if source.exists():
                shutil.move(str(source), str(automation_dir / script))
                self.cleanup_stats["files_moved"] += 1
                print(f"🤖 Moved: {script} -> tools/automation/")

    def cleanup_temp_files(self):
        """Usuwa tymczasowe pliki"""
        temp_patterns = ["*.pyc", "__pycache__", "*.tmp", ".DS_Store", "Thumbs.db"]

        removed_count = 0
        for pattern in temp_patterns:
            for file_path in self.project_root.rglob(pattern):
                if file_path.is_file():
                    file_path.unlink()
                    removed_count += 1
                elif file_path.is_dir():
                    shutil.rmtree(file_path)
                    removed_count += 1

        self.cleanup_stats["files_removed"] = removed_count
        if removed_count > 0:
            print(f"🗑️  Removed {removed_count} temporary files")

    def create_project_index(self):
        """Tworzy indeks projektu"""
        index = {
            "project": "XSS Vibes V2",
            "last_cleanup": datetime.now().isoformat(),
            "structure": {
                "analysis_results/": {
                    "github/": "GitHub HTML analysis results",
                    "ai_tools/": "AI tools testing results",
                    "reports/": "Generated HTML reports",
                },
                "tools/": {
                    "integration/": "Payload integration scripts",
                    "analysis/": "Code analysis tools",
                    "automation/": "Automated testing scripts",
                },
                "xss_vibes/": "Main package code",
                "scripts/": "Core project scripts",
                "docs/": "Documentation files",
            },
            "ai_tools": {
                "ai_context_extractor.py": "AI-powered context analysis",
                "ai_domfuzz.py": "Smart DOM fuzzing tool",
                "report_gen.py": "HTML report generator",
            },
            "cleanup_stats": self.cleanup_stats,
        }

        index_file = self.project_root / "PROJECT_INDEX.json"
        with open(index_file, "w") as f:
            json.dump(index, f, indent=2)

        print(f"📋 Created project index: {index_file}")

    def optimize_json_files(self):
        """Optymalizuje pliki JSON"""
        json_files = list(self.project_root.rglob("*.json"))
        optimized = 0

        for json_file in json_files:
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)

                # Kompaktuj JSON
                with open(json_file, "w") as f:
                    json.dump(data, f, separators=(",", ":"))

                optimized += 1
            except:
                continue

        self.cleanup_stats["files_optimized"] = optimized
        print(f"⚡ Optimized {optimized} JSON files")

    def run_cleanup(self):
        """Wykonuje pełne porządki"""
        print("🧹 XSS Vibes - Project Cleanup Starting...")
        print("=" * 50)

        self.create_directory_structure()
        self.organize_analysis_files()
        self.organize_scripts()
        self.cleanup_temp_files()
        self.optimize_json_files()
        self.create_project_index()

        print()
        print("📊 CLEANUP SUMMARY:")
        print(f"  📁 Directories created: {self.cleanup_stats['directories_created']}")
        print(f"  📄 Files moved: {self.cleanup_stats['files_moved']}")
        print(f"  🗑️  Files removed: {self.cleanup_stats['files_removed']}")
        print(f"  ⚡ Files optimized: {self.cleanup_stats['files_optimized']}")
        print()
        print("✅ XSS Vibes project cleanup complete!")
        print("🚀 Project structure optimized for development!")


if __name__ == "__main__":
    cleanup = XSSVibesCleanup()
    cleanup.run_cleanup()
