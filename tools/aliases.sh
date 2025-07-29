#!/bin/bash
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
