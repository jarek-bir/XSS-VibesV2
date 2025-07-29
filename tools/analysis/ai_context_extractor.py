#!/usr/bin/env python3
"""
XSS Vibes - AI Context Extractor
Analyzes JavaScript files and suggests optimal XSS templates and contexts using AI pattern recognition
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class AIContextExtractor:
    def __init__(self):
        self.patterns = {
            # React/JSX patterns
            "react": {
                "patterns": [
                    r"dangerouslySetInnerHTML",
                    r"React\.createElement",
                    r"ReactDOM\.render",
                    r"useState|useEffect|useContext",
                    r"this\.setState",
                    r"props\.\w+",
                    r"jsx|tsx",
                ],
                "suggested_template": "react_binding",
                "contexts": [
                    "dangerouslySetInnerHTML",
                    "JSX injection",
                    "React DOM",
                    "useState injection",
                ],
                "priority": 9,
            },
            # Web Components patterns
            "web_components": {
                "patterns": [
                    r"customElements\.define",
                    r"attachShadow",
                    r"shadowRoot",
                    r"HTMLElement",
                    r"connectedCallback",
                    r"slot\s*>",
                    r"<template",
                ],
                "suggested_template": "web_components",
                "contexts": [
                    "Custom elements",
                    "Shadow DOM",
                    "Slot injection",
                    "Template cloning",
                ],
                "priority": 8,
            },
            # Service Worker patterns
            "service_worker": {
                "patterns": [
                    r"serviceWorker\.register",
                    r"self\.addEventListener",
                    r"fetch.*event",
                    r"caches\.open",
                    r"postMessage",
                    r"importScripts",
                    r"skipWaiting",
                ],
                "suggested_template": "service_worker",
                "contexts": [
                    "SW fetch interception",
                    "Cache poisoning",
                    "postMessage",
                    "importScripts",
                ],
                "priority": 8,
            },
            # JSONP patterns
            "jsonp": {
                "patterns": [
                    r"callback\s*=",
                    r"jsonp",
                    r"script.*src.*callback",
                    r"window\[\w+\]",
                    r"eval\s*\(",
                    r"Function\s*\(",
                    r"JSONP",
                ],
                "suggested_template": "jsonp",
                "contexts": [
                    "JSONP callback",
                    "Dynamic script loading",
                    "eval injection",
                ],
                "priority": 7,
            },
            # DOM Sinks patterns
            "dom_sinks": {
                "patterns": [
                    r"innerHTML\s*=",
                    r"outerHTML\s*=",
                    r"document\.write",
                    r"document\.writeln",
                    r"insertAdjacentHTML",
                    r"\.after\s*\(",
                    r"\.before\s*\(",
                    r"\.replaceWith",
                ],
                "suggested_template": "dom_sinks",
                "contexts": [
                    "innerHTML",
                    "outerHTML",
                    "document.write",
                    "insertAdjacentHTML",
                ],
                "priority": 9,
            },
            # Iframe patterns
            "iframe_sandbox": {
                "patterns": [
                    r"iframe.*sandbox",
                    r"srcdoc\s*=",
                    r"postMessage",
                    r"contentWindow",
                    r"frames\[",
                    r"parent\.postMessage",
                    r"data:text/html",
                ],
                "suggested_template": "iframe_sandbox",
                "contexts": [
                    "iframe srcdoc",
                    "postMessage",
                    "sandbox bypass",
                    "data URLs",
                ],
                "priority": 7,
            },
            # CSP bypass patterns
            "csp_bypass": {
                "patterns": [
                    r"Content-Security-Policy",
                    r"'unsafe-inline'",
                    r"'unsafe-eval'",
                    r"nonce-",
                    r"base.*href",
                    r"meta.*refresh",
                    r"object.*data",
                ],
                "suggested_template": "csp_blocked",
                "contexts": ["CSP bypass", "base tag", "meta refresh", "object data"],
                "priority": 8,
            },
            # SPA Framework patterns
            "spa_framework": {
                "patterns": [
                    r"angular\.|ng-",
                    r"vue\.|v-",
                    r"\.route|router",
                    r"history\.pushState",
                    r"location\.hash",
                    r"hashchange",
                    r"popstate",
                ],
                "suggested_template": "spa_framework",
                "contexts": ["SPA routing", "hash manipulation", "history API"],
                "priority": 6,
            },
            # Template engines
            "template_engines": {
                "patterns": [
                    r"{{.*}}",
                    r"<%.*%>",
                    r"handlebars",
                    r"mustache",
                    r"ejs",
                    r"jade|pug",
                    r"template\s*literal",
                ],
                "suggested_template": "dom_sinks",
                "contexts": [
                    "Template injection",
                    "Server-side templates",
                    "Client-side templates",
                ],
                "priority": 7,
            },
        }

        self.advanced_patterns = {
            # Advanced JavaScript patterns
            "eval_patterns": [
                r"eval\s*\(",
                r"Function\s*\(",
                r"setTimeout\s*\([^,]*['\"`]",
                r"setInterval\s*\([^,]*['\"`]",
                r"execScript",
                r"window\[.*\]\s*\(",
            ],
            "dom_patterns": [
                r"createElement\s*\(",
                r"createTextNode",
                r"appendChild",
                r"insertBefore",
                r"replaceChild",
                r"cloneNode",
                r"importNode",
            ],
            "event_patterns": [
                r"addEventListener",
                r"on\w+\s*=",
                r"onclick|onload|onerror|onmouseover",
                r"dispatchEvent",
                r"createEvent",
                r"initEvent",
            ],
            "ajax_patterns": [
                r"XMLHttpRequest",
                r"fetch\s*\(",
                r"\.ajax\s*\(",
                r"axios\.",
                r"$.get|$.post",
                r"xhr\.",
            ],
        }

    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a JavaScript file and extract XSS contexts"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Cannot read file: {e}"}

        # Basic file info
        file_info = {
            "file": file_path,
            "size": len(content),
            "lines": len(content.splitlines()),
        }

        # Detect main patterns
        detected_patterns = self._detect_patterns(content)

        # Get suggestions
        suggestions = self._get_suggestions(detected_patterns)

        # Extract specific contexts
        contexts = self._extract_contexts(content)

        # Risk assessment
        risk_score = self._calculate_risk(detected_patterns, contexts)

        return {
            "file_info": file_info,
            "detected_patterns": detected_patterns,
            "suggested_templates": suggestions,
            "contexts": contexts,
            "risk_score": risk_score,
            "recommendations": self._get_recommendations(suggestions, contexts),
        }

    def _detect_patterns(self, content: str) -> Dict:
        """Detect patterns in JavaScript content"""
        detected = {}

        for category, pattern_info in self.patterns.items():
            matches = []
            for pattern in pattern_info["patterns"]:
                found = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if found:
                    matches.extend(found)

            if matches:
                detected[category] = {
                    "matches": len(matches),
                    "priority": pattern_info["priority"],
                    "template": pattern_info["suggested_template"],
                    "contexts": pattern_info["contexts"],
                }

        # Detect advanced patterns
        for adv_category, patterns in self.advanced_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                matches.extend(found)

            if matches:
                detected[f"advanced_{adv_category}"] = {
                    "matches": len(matches),
                    "priority": 6,
                }

        return detected

    def _get_suggestions(self, detected_patterns: Dict) -> List[Dict]:
        """Get template suggestions based on detected patterns"""
        suggestions = []

        # Sort by priority and matches
        sorted_patterns = sorted(
            detected_patterns.items(),
            key=lambda x: (x[1].get("priority", 0), x[1].get("matches", 0)),
            reverse=True,
        )

        for pattern_name, pattern_data in sorted_patterns:
            if "template" in pattern_data:
                suggestion = {
                    "template": pattern_data["template"],
                    "reason": pattern_name,
                    "confidence": min(pattern_data["matches"] * 10, 100),
                    "priority": pattern_data["priority"],
                    "contexts": pattern_data.get("contexts", []),
                }
                suggestions.append(suggestion)

        return suggestions

    def _extract_contexts(self, content: str) -> Dict:
        """Extract specific XSS contexts from content"""
        contexts = {
            "dom_sinks": [],
            "event_handlers": [],
            "dynamic_execution": [],
            "template_contexts": [],
            "user_input_sinks": [],
        }

        # DOM sinks
        dom_sink_patterns = [
            r"(\w+)\.innerHTML\s*=\s*([^;]+)",
            r"(\w+)\.outerHTML\s*=\s*([^;]+)",
            r"document\.write\s*\(([^)]+)\)",
            r"(\w+)\.insertAdjacentHTML\s*\([^,]+,\s*([^)]+)\)",
        ]

        for pattern in dom_sink_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                contexts["dom_sinks"].append(
                    {
                        "sink": match[0] if len(match) > 1 else "unknown",
                        "value": match[1] if len(match) > 1 else match[0],
                    }
                )

        # Event handlers
        event_patterns = [
            r"(\w+)\.addEventListener\s*\(\s*['\"](\w+)['\"],\s*([^,)]+)",
            r"(\w+)\.on(\w+)\s*=\s*([^;]+)",
        ]

        for pattern in event_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                contexts["event_handlers"].append(
                    {
                        "element": match[0],
                        "event": match[1],
                        "handler": match[2] if len(match) > 2 else "unknown",
                    }
                )

        # Dynamic execution
        exec_patterns = [
            r"eval\s*\(([^)]+)\)",
            r"Function\s*\(([^)]+)\)",
            r"setTimeout\s*\(\s*['\"]([^'\"]+)['\"]",
            r"setInterval\s*\(\s*['\"]([^'\"]+)['\"]\)",
        ]

        for pattern in exec_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                contexts["dynamic_execution"].append(match)

        return contexts

    def _calculate_risk(self, patterns: Dict, contexts: Dict) -> Dict:
        """Calculate XSS risk score"""
        base_score = 0
        risk_factors = []

        # Pattern-based scoring
        for pattern_name, pattern_data in patterns.items():
            if pattern_data.get("priority", 0) >= 8:
                base_score += 30
                risk_factors.append(f"High-risk pattern: {pattern_name}")
            elif pattern_data.get("priority", 0) >= 6:
                base_score += 15
                risk_factors.append(f"Medium-risk pattern: {pattern_name}")
            else:
                base_score += 5

        # Context-based scoring
        if contexts["dom_sinks"]:
            base_score += len(contexts["dom_sinks"]) * 10
            risk_factors.append(f"DOM sinks found: {len(contexts['dom_sinks'])}")

        if contexts["dynamic_execution"]:
            base_score += len(contexts["dynamic_execution"]) * 20
            risk_factors.append(
                f"Dynamic execution: {len(contexts['dynamic_execution'])}"
            )

        if contexts["event_handlers"]:
            base_score += len(contexts["event_handlers"]) * 5
            risk_factors.append(f"Event handlers: {len(contexts['event_handlers'])}")

        # Cap at 100
        final_score = min(base_score, 100)

        risk_level = "LOW"
        if final_score >= 70:
            risk_level = "CRITICAL"
        elif final_score >= 50:
            risk_level = "HIGH"
        elif final_score >= 30:
            risk_level = "MEDIUM"

        return {"score": final_score, "level": risk_level, "factors": risk_factors}

    def _get_recommendations(
        self, suggestions: List[Dict], contexts: Dict
    ) -> List[str]:
        """Get testing recommendations"""
        recommendations = []

        if suggestions:
            top_suggestion = suggestions[0]
            recommendations.append(
                f"🎯 PRIMARY: Use template '{top_suggestion['template']}' "
                f"(confidence: {top_suggestion['confidence']}%)"
            )

        if contexts["dom_sinks"]:
            recommendations.append(
                f"🔥 Test DOM sinks with innerHTML/outerHTML payloads ({len(contexts['dom_sinks'])} found)"
            )

        if contexts["dynamic_execution"]:
            recommendations.append(
                f"⚡ Test dynamic execution contexts with eval/Function payloads ({len(contexts['dynamic_execution'])} found)"
            )

        # Template-specific recommendations
        for suggestion in suggestions[:3]:  # Top 3 suggestions
            template = suggestion["template"]
            if template == "react_binding":
                recommendations.append(
                    "🔸 Test dangerouslySetInnerHTML and JSX injection points"
                )
            elif template == "web_components":
                recommendations.append(
                    "🔸 Test Custom Elements and Shadow DOM injection"
                )
            elif template == "service_worker":
                recommendations.append(
                    "🔸 Test Service Worker fetch interception and cache poisoning"
                )
            elif template == "jsonp":
                recommendations.append(
                    "🔸 Test JSONP callback manipulation and script injection"
                )

        return recommendations

    def analyze_directory(
        self, directory: str, extensions: Optional[List[str]] = None
    ) -> Dict:
        """Analyze all JavaScript files in a directory"""
        if extensions is None:
            extensions = [".js", ".jsx", ".ts", ".tsx", ".vue", ".html", ".htm"]

        results = {
            "directory": directory,
            "total_files": 0,
            "analyzed_files": 0,
            "files": [],
            "summary": {
                "templates_suggested": {},
                "total_risk_score": 0,
                "high_risk_files": [],
            },
        }

        directory_path = Path(directory)

        for ext in extensions:
            for file_path in directory_path.rglob(f"*{ext}"):
                results["total_files"] += 1

                if file_path.is_file():
                    analysis = self.analyze_file(str(file_path))

                    if "error" not in analysis:
                        results["analyzed_files"] += 1
                        results["files"].append(analysis)

                        # Update summary
                        risk_score = analysis["risk_score"]["score"]
                        results["summary"]["total_risk_score"] += risk_score

                        if risk_score >= 50:
                            results["summary"]["high_risk_files"].append(
                                {
                                    "file": str(file_path),
                                    "risk_score": risk_score,
                                    "level": analysis["risk_score"]["level"],
                                }
                            )

                        # Count template suggestions
                        for suggestion in analysis["suggested_templates"]:
                            template = suggestion["template"]
                            if (
                                template
                                not in results["summary"]["templates_suggested"]
                            ):
                                results["summary"]["templates_suggested"][template] = 0
                            results["summary"]["templates_suggested"][template] += 1

        return results

    def generate_report(
        self, analysis_result: Dict, output_file: Optional[str] = None
    ) -> str:
        """Generate a comprehensive analysis report"""
        if "files" in analysis_result:
            # Directory analysis
            return self._generate_directory_report(analysis_result, output_file)
        else:
            # Single file analysis
            return self._generate_file_report(analysis_result, output_file)

    def _generate_file_report(
        self, analysis: Dict, output_file: Optional[str] = None
    ) -> str:
        """Generate report for single file analysis"""
        report = f"""
# 🧠 XSS Vibes - AI Context Analysis Report

## 📄 File Information
- **File**: {analysis['file_info']['file']}
- **Size**: {analysis['file_info']['size']} bytes
- **Lines**: {analysis['file_info']['lines']}

## 🎯 Risk Assessment
- **Score**: {analysis['risk_score']['score']}/100
- **Level**: {analysis['risk_score']['level']}

### Risk Factors:
"""
        for factor in analysis["risk_score"]["factors"]:
            report += f"- {factor}\n"

        report += "\n## 🎯 Template Suggestions\n"
        for i, suggestion in enumerate(analysis["suggested_templates"], 1):
            report += f"""
### {i}. {suggestion['template']}
- **Confidence**: {suggestion['confidence']}%
- **Priority**: {suggestion['priority']}/10
- **Reason**: {suggestion['reason']}
- **Contexts**: {', '.join(suggestion['contexts'])}
"""

        report += "\n## 🔍 Detected Contexts\n"
        for context_type, contexts in analysis["contexts"].items():
            if contexts:
                report += f"\n### {context_type.replace('_', ' ').title()}\n"
                for context in contexts:
                    if isinstance(context, dict):
                        report += f"- {context}\n"
                    else:
                        report += f"- {context}\n"

        report += "\n## 💡 Recommendations\n"
        for rec in analysis["recommendations"]:
            report += f"- {rec}\n"

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)

        return report

    def _generate_directory_report(
        self, analysis: Dict, output_file: Optional[str] = None
    ) -> str:
        """Generate report for directory analysis"""
        report = f"""
# 🧠 XSS Vibes - AI Directory Analysis Report

## 📊 Summary
- **Directory**: {analysis['directory']}
- **Total Files**: {analysis['total_files']}
- **Analyzed Files**: {analysis['analyzed_files']}
- **Average Risk Score**: {analysis['summary']['total_risk_score'] // max(analysis['analyzed_files'], 1)}

## 🚨 High Risk Files
"""
        for file_info in analysis["summary"]["high_risk_files"]:
            report += f"- **{file_info['file']}** - {file_info['level']} ({file_info['risk_score']}/100)\n"

        report += "\n## 🎯 Template Recommendations\n"
        for template, count in sorted(
            analysis["summary"]["templates_suggested"].items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            report += f"- **{template}**: {count} files\n"

        report += "\n## 📋 Detailed File Analysis\n"
        for file_analysis in analysis["files"]:
            if (
                file_analysis["risk_score"]["score"] >= 30
            ):  # Only show medium+ risk files
                report += f"""
### {file_analysis['file_info']['file']}
- **Risk Score**: {file_analysis['risk_score']['score']}/100 ({file_analysis['risk_score']['level']})
- **Top Template**: {file_analysis['suggested_templates'][0]['template'] if file_analysis['suggested_templates'] else 'None'}
- **Key Contexts**: {len(file_analysis['contexts']['dom_sinks'])} DOM sinks, {len(file_analysis['contexts']['dynamic_execution'])} dynamic execution
"""

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)

        return report


def main():
    parser = argparse.ArgumentParser(description="XSS Vibes - AI Context Extractor")
    parser.add_argument("target", help="File or directory to analyze")
    parser.add_argument("--output", "-o", help="Output report file")
    parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text", help="Output format"
    )
    parser.add_argument(
        "--extensions",
        "-e",
        nargs="+",
        default=[".js", ".jsx", ".ts", ".tsx", ".vue", ".html"],
        help="File extensions to analyze",
    )

    args = parser.parse_args()

    extractor = AIContextExtractor()

    print("🧠 XSS Vibes - AI Context Extractor")
    print("=" * 50)

    target_path = Path(args.target)

    if target_path.is_file():
        print(f"📄 Analyzing file: {args.target}")
        result = extractor.analyze_file(args.target)
    elif target_path.is_dir():
        print(f"📁 Analyzing directory: {args.target}")
        result = extractor.analyze_directory(args.target, args.extensions)
    else:
        print(f"❌ Target not found: {args.target}")
        return

    if args.format == "json":
        output = json.dumps(result, indent=2, ensure_ascii=False)
    else:
        output = extractor.generate_report(result, args.output)

    if args.output and args.format == "json":
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"📄 Report saved to: {args.output}")
    elif not args.output:
        print("\n" + output)

    # Show quick summary
    if isinstance(result, dict) and "summary" in result:
        # Directory analysis
        print(f"\n🎯 Quick Summary:")
        print(f"   Files analyzed: {result['analyzed_files']}")
        print(f"   High risk files: {len(result['summary']['high_risk_files'])}")
        top_template = (
            max(result["summary"]["templates_suggested"].items(), key=lambda x: x[1])
            if result["summary"]["templates_suggested"]
            else None
        )
        if top_template:
            print(f"   Top template: {top_template[0]} ({top_template[1]} files)")
    elif isinstance(result, dict) and "risk_score" in result:
        # Single file analysis
        print(f"\n🎯 Quick Summary:")
        print(
            f"   Risk score: {result['risk_score']['score']}/100 ({result['risk_score']['level']})"
        )
        if result["suggested_templates"]:
            print(f"   Best template: {result['suggested_templates'][0]['template']}")


if __name__ == "__main__":
    main()
