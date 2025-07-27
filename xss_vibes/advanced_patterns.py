#!/usr/bin/env python3
"""
Advanced Pattern System for XSS Vibes - Similar to gf tool functionality.

This module provides advanced pattern matching for payload selection,
vulnerability detection, and automated scanning workflows.
"""

import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set, Pattern, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("xss_vibes.patterns")


class PatternType(Enum):
    """Types of patterns for different use cases."""

    XSS_DETECTION = "xss_detection"
    WAF_BYPASS = "waf_bypass"
    CONTEXT_INJECTION = "context_injection"
    PARAMETER_DISCOVERY = "parameter_discovery"
    PAYLOAD_SELECTION = "payload_selection"
    VULNERABILITY_VALIDATION = "vulnerability_validation"
    ENCODING_DETECTION = "encoding_detection"
    REFLECTION_ANALYSIS = "reflection_analysis"


@dataclass
class XSSPattern:
    """Advanced XSS pattern definition."""

    name: str
    description: str
    pattern_type: PatternType
    regex_patterns: List[str]
    payload_filters: List[str]
    context_hints: List[str]
    waf_targets: List[str]
    priority: int = 5
    active: bool = True
    examples: Optional[List[str]] = None


class AdvancedPatternEngine:
    """Advanced pattern matching engine for XSS detection and payload selection."""

    def __init__(self):
        """Initialize pattern engine."""
        self.patterns: Dict[str, XSSPattern] = {}
        self.compiled_patterns: Dict[str, List[Pattern]] = {}
        self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load default XSS detection patterns."""

        # XSS Detection Patterns
        self.add_pattern(
            XSSPattern(
                name="script_tag_basic",
                description="Basic <script> tag detection",
                pattern_type=PatternType.XSS_DETECTION,
                regex_patterns=[
                    r"<script[^>]*>.*?</script>",
                    r"<script[^>]*>.*?alert\s*\(",
                    r"<script[^>]*>.*?prompt\s*\(",
                    r"<script[^>]*>.*?confirm\s*\(",
                ],
                payload_filters=["script", "alert", "prompt", "confirm"],
                context_hints=["html_content", "html_attribute"],
                waf_targets=["generic"],
                priority=8,
                examples=[
                    "<script>alert(1)</script>",
                    "<script>prompt('XSS')</script>",
                ],
            )
        )

        self.add_pattern(
            XSSPattern(
                name="event_handler_injection",
                description="Event handler based XSS",
                pattern_type=PatternType.XSS_DETECTION,
                regex_patterns=[
                    r"on\w+\s*=\s*[\"']?[^\"'>]*alert\s*\(",
                    r"on\w+\s*=\s*[\"']?[^\"'>]*prompt\s*\(",
                    r"on\w+\s*=\s*[\"']?[^\"'>]*eval\s*\(",
                    r"on\w+\s*=\s*[\"']?[^\"'>]*javascript:",
                ],
                payload_filters=[
                    "onerror",
                    "onload",
                    "onclick",
                    "onmouseover",
                    "onfocus",
                ],
                context_hints=["html_attribute", "tag_attribute"],
                waf_targets=["generic", "cloudflare", "akamai"],
                priority=9,
                examples=['onerror="alert(1)"', 'onload="prompt(document.domain)"'],
            )
        )

        self.add_pattern(
            XSSPattern(
                name="svg_xss_vectors",
                description="SVG-based XSS patterns",
                pattern_type=PatternType.XSS_DETECTION,
                regex_patterns=[
                    r"<svg[^>]*onload\s*=\s*[\"']?[^\"'>]*alert\s*\(",
                    r"<svg[^>]*>.*?<script",
                    r"<svg[^>]*>.*?alert\s*\(",
                ],
                payload_filters=["svg", "onload"],
                context_hints=["html_content", "xml_context"],
                waf_targets=["generic", "modsecurity"],
                priority=7,
                examples=[
                    "<svg onload=alert(1)>",
                    "<svg><script>alert(1)</script></svg>",
                ],
            )
        )

        # WAF Bypass Patterns
        self.add_pattern(
            XSSPattern(
                name="cloudflare_bypass",
                description="Cloudflare WAF bypass techniques",
                pattern_type=PatternType.WAF_BYPASS,
                regex_patterns=[
                    r"&#x\w+;",  # HTML entities
                    r"\\u\w{4}",  # Unicode escapes
                    r"String\.fromCharCode\(",  # Character code obfuscation
                    r"eval\s*\(\s*[\"'].*?[\"']\s*\)",  # Eval obfuscation
                ],
                payload_filters=["fromcharcode", "unicode", "entity"],
                context_hints=["javascript_context"],
                waf_targets=["cloudflare"],
                priority=10,
                examples=[
                    "String.fromCharCode(97,108,101,114,116)",
                    "\\u0061\\u006c\\u0065\\u0072\\u0074",
                ],
            )
        )

        self.add_pattern(
            XSSPattern(
                name="akamai_evasion",
                description="Akamai WAF evasion patterns",
                pattern_type=PatternType.WAF_BYPASS,
                regex_patterns=[
                    r"new\s+Function\s*\(",
                    r"constructor\s*\(",
                    r"\[.*?\]\[.*?\]",  # Bracket notation
                    r"top\[.*?\]",
                ],
                payload_filters=["function", "constructor", "bracket"],
                context_hints=["javascript_context"],
                waf_targets=["akamai"],
                priority=9,
                examples=["new Function('alert(1)')()", "top['alert'](1)"],
            )
        )

        # Context Injection Patterns
        self.add_pattern(
            XSSPattern(
                name="javascript_string_escape",
                description="JavaScript string context escapes",
                pattern_type=PatternType.CONTEXT_INJECTION,
                regex_patterns=[
                    r"[\"'];\s*alert\s*\(",
                    r"[\"']\s*\+\s*alert\s*\(",
                    r"[\"']\s*-\s*alert\s*\(",
                ],
                payload_filters=["escape", "string", "concat"],
                context_hints=["javascript_string"],
                waf_targets=["generic"],
                priority=8,
                examples=["'; alert(1); //", "' + alert(1) + '"],
            )
        )

        self.add_pattern(
            XSSPattern(
                name="html_attribute_escape",
                description="HTML attribute context escapes",
                pattern_type=PatternType.CONTEXT_INJECTION,
                regex_patterns=[
                    r"[\"']\s*onload\s*=\s*[\"']?alert\s*\(",
                    r"[\"']\s*onerror\s*=\s*[\"']?alert\s*\(",
                    r"[\"']\s*><script",
                ],
                payload_filters=["attribute", "escape"],
                context_hints=["html_attribute"],
                waf_targets=["generic"],
                priority=7,
                examples=['" onload="alert(1)', "' onerror='alert(1)'"],
            )
        )

        # Parameter Discovery Patterns
        self.add_pattern(
            XSSPattern(
                name="reflected_parameter_detection",
                description="Detect reflected parameters in responses",
                pattern_type=PatternType.PARAMETER_DISCOVERY,
                regex_patterns=[
                    r"<input[^>]*value\s*=\s*[\"']?[^\"'>]*\{PARAM\}",
                    r"<[^>]*[\"']\s*[^\"'>]*\{PARAM\}[^\"'>]*[\"']",
                    r"var\s+\w+\s*=\s*[\"']?[^\"'>]*\{PARAM\}",
                ],
                payload_filters=["reflection", "parameter"],
                context_hints=["parameter_reflection"],
                waf_targets=["generic"],
                priority=6,
            )
        )

        # Vulnerability Validation Patterns
        self.add_pattern(
            XSSPattern(
                name="successful_xss_execution",
                description="Patterns indicating successful XSS execution",
                pattern_type=PatternType.VULNERABILITY_VALIDATION,
                regex_patterns=[
                    r"alert\s*\(\s*[\"']?1[\"']?\s*\)",
                    r"prompt\s*\(\s*[\"']?.*?[\"']?\s*\)",
                    r"confirm\s*\(\s*[\"']?.*?[\"']?\s*\)",
                    r"console\.log\s*\(\s*[\"']?.*?[\"']?\s*\)",
                ],
                payload_filters=["execution", "validation"],
                context_hints=["executed"],
                waf_targets=["generic"],
                priority=10,
            )
        )

        logger.info(f"Loaded {len(self.patterns)} default XSS patterns")

    def add_pattern(self, pattern: XSSPattern) -> None:
        """Add a new pattern to the engine."""
        self.patterns[pattern.name] = pattern

        # Compile regex patterns for performance
        compiled = []
        for regex_pattern in pattern.regex_patterns:
            try:
                compiled.append(re.compile(regex_pattern, re.IGNORECASE | re.DOTALL))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{regex_pattern}': {e}")

        self.compiled_patterns[pattern.name] = compiled
        logger.debug(f"Added pattern: {pattern.name}")

    def save_pattern(
        self, pattern: XSSPattern, file_path: Optional[Path] = None
    ) -> None:
        """Save a pattern to file."""
        if file_path is None:
            file_path = (
                Path(__file__).parent / "data" / "patterns" / f"{pattern.name}.json"
            )

        file_path.parent.mkdir(parents=True, exist_ok=True)

        pattern_data = {
            "name": pattern.name,
            "description": pattern.description,
            "pattern_type": pattern.pattern_type.value,
            "regex_patterns": pattern.regex_patterns,
            "payload_filters": pattern.payload_filters,
            "context_hints": pattern.context_hints,
            "waf_targets": pattern.waf_targets,
            "priority": pattern.priority,
            "active": pattern.active,
            "examples": pattern.examples or [],
        }

        with open(file_path, "w") as f:
            json.dump(pattern_data, f, indent=2)

        logger.info(f"Saved pattern '{pattern.name}' to {file_path}")

    def load_pattern_from_file(self, file_path: Path) -> Optional[XSSPattern]:
        """Load a pattern from file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            pattern = XSSPattern(
                name=data["name"],
                description=data["description"],
                pattern_type=PatternType(data["pattern_type"]),
                regex_patterns=data["regex_patterns"],
                payload_filters=data["payload_filters"],
                context_hints=data["context_hints"],
                waf_targets=data["waf_targets"],
                priority=data.get("priority", 5),
                active=data.get("active", True),
                examples=data.get("examples", []),
            )

            self.add_pattern(pattern)
            return pattern

        except Exception as e:
            logger.error(f"Error loading pattern from {file_path}: {e}")
            return None

    def list_patterns(
        self, pattern_type: Optional[PatternType] = None
    ) -> List[XSSPattern]:
        """List available patterns, optionally filtered by type."""
        patterns = list(self.patterns.values())

        if pattern_type:
            patterns = [p for p in patterns if p.pattern_type == pattern_type]

        return sorted(patterns, key=lambda p: p.priority, reverse=True)

    def match_patterns(
        self,
        text: str,
        pattern_type: Optional[PatternType] = None,
        waf_target: Optional[str] = None,
        min_priority: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Match text against patterns and return results.

        Args:
            text: Text to match against
            pattern_type: Filter by pattern type
            waf_target: Filter by WAF target
            min_priority: Minimum pattern priority

        Returns:
            List of match results with pattern info
        """
        matches = []

        for pattern_name, pattern in self.patterns.items():
            if not pattern.active or pattern.priority < min_priority:
                continue

            if pattern_type and pattern.pattern_type != pattern_type:
                continue

            if waf_target and waf_target not in pattern.waf_targets:
                continue

            # Test compiled regex patterns
            pattern_matches = []
            for compiled_regex in self.compiled_patterns.get(pattern_name, []):
                regex_matches = compiled_regex.findall(text)
                if regex_matches:
                    pattern_matches.extend(regex_matches)

            if pattern_matches:
                matches.append(
                    {
                        "pattern_name": pattern.name,
                        "pattern_type": pattern.pattern_type.value,
                        "description": pattern.description,
                        "priority": pattern.priority,
                        "matches": pattern_matches,
                        "match_count": len(pattern_matches),
                        "waf_targets": pattern.waf_targets,
                        "context_hints": pattern.context_hints,
                    }
                )

        # Sort by priority and match count
        matches.sort(key=lambda x: (x["priority"], x["match_count"]), reverse=True)
        return matches

    def suggest_payloads(
        self, text: str, context: Optional[str] = None, waf_target: Optional[str] = None
    ) -> List[str]:
        """
        Suggest appropriate payloads based on pattern analysis.

        Args:
            text: Response text to analyze
            context: Injection context hint
            waf_target: Target WAF type

        Returns:
            List of suggested payload patterns
        """
        suggestions = []

        # Match detection patterns
        matches = self.match_patterns(
            text, pattern_type=PatternType.XSS_DETECTION, waf_target=waf_target
        )

        for match in matches:
            pattern = self.patterns[match["pattern_name"]]
            suggestions.extend(pattern.payload_filters)

        # Add context-specific suggestions
        if context:
            context_matches = self.match_patterns(
                text, pattern_type=PatternType.CONTEXT_INJECTION
            )

            for match in context_matches:
                pattern = self.patterns[match["pattern_name"]]
                if context in pattern.context_hints:
                    suggestions.extend(pattern.payload_filters)

        # Remove duplicates and return
        return list(set(suggestions))

    def analyze_reflection(
        self, original_payload: str, response_text: str
    ) -> Dict[str, Any]:
        """
        Analyze how a payload is reflected in the response.

        Args:
            original_payload: Original payload sent
            response_text: Response text received

        Returns:
            Analysis results with reflection details
        """
        analysis = {
            "payload": original_payload,
            "reflected": original_payload in response_text,
            "reflection_count": response_text.count(original_payload),
            "reflection_contexts": [],
            "encoding_detected": [],
            "filter_bypass_potential": 0,
            "suggested_modifications": [],
        }

        if analysis["reflected"]:
            # Analyze reflection contexts
            matches = self.match_patterns(
                response_text, pattern_type=PatternType.REFLECTION_ANALYSIS
            )

            analysis["reflection_contexts"] = [m["pattern_name"] for m in matches]

            # Check for encoding
            encoding_matches = self.match_patterns(
                response_text, pattern_type=PatternType.ENCODING_DETECTION
            )

            analysis["encoding_detected"] = [
                m["pattern_name"] for m in encoding_matches
            ]

            # Calculate bypass potential
            if len(analysis["reflection_contexts"]) > 1:
                analysis["filter_bypass_potential"] += 3
            if len(analysis["encoding_detected"]) == 0:
                analysis["filter_bypass_potential"] += 5

            # Suggest modifications
            suggestions = self.suggest_payloads(response_text)
            analysis["suggested_modifications"] = suggestions

        return analysis

    def generate_pattern_report(self) -> Dict[str, Any]:
        """Generate a comprehensive pattern report."""
        report = {
            "total_patterns": len(self.patterns),
            "active_patterns": len([p for p in self.patterns.values() if p.active]),
            "pattern_types": {},
            "waf_coverage": {},
            "priority_distribution": {},
            "patterns_by_type": {},
        }

        # Count by type
        for pattern in self.patterns.values():
            ptype = pattern.pattern_type.value
            report["pattern_types"][ptype] = report["pattern_types"].get(ptype, 0) + 1

            if ptype not in report["patterns_by_type"]:
                report["patterns_by_type"][ptype] = []
            report["patterns_by_type"][ptype].append(pattern.name)

        # Count WAF coverage
        for pattern in self.patterns.values():
            for waf in pattern.waf_targets:
                report["waf_coverage"][waf] = report["waf_coverage"].get(waf, 0) + 1

        # Priority distribution
        for pattern in self.patterns.values():
            priority = pattern.priority
            report["priority_distribution"][priority] = (
                report["priority_distribution"].get(priority, 0) + 1
            )

        return report


# CLI Integration Functions


def pattern_list_command(pattern_type: Optional[str] = None) -> None:
    """CLI command to list patterns."""
    engine = AdvancedPatternEngine()

    ptype = PatternType(pattern_type) if pattern_type else None
    patterns = engine.list_patterns(ptype)

    print(f"\n🎯 XSS Vibes - Advanced Patterns ({len(patterns)} patterns)")
    print("=" * 60)

    for pattern in patterns:
        print(f"\n📋 {pattern.name}")
        print(f"   Type: {pattern.pattern_type.value}")
        print(f"   Priority: {pattern.priority}")
        print(f"   WAF Targets: {', '.join(pattern.waf_targets)}")
        print(f"   Description: {pattern.description}")

        if pattern.examples:
            print(f"   Examples: {', '.join(pattern.examples[:2])}")


def pattern_match_command(text: str, pattern_type: Optional[str] = None) -> None:
    """CLI command to match text against patterns."""
    engine = AdvancedPatternEngine()

    ptype = PatternType(pattern_type) if pattern_type else None
    matches = engine.match_patterns(text, ptype)

    print(f"\n🔍 Pattern Matching Results ({len(matches)} matches)")
    print("=" * 60)

    for match in matches:
        print(f"\n✅ {match['pattern_name']}")
        print(f"   Type: {match['pattern_type']}")
        print(f"   Priority: {match['priority']}")
        print(f"   Matches: {match['match_count']}")
        print(f"   WAF Targets: {', '.join(match['waf_targets'])}")
        print(f"   Description: {match['description']}")


def pattern_suggest_command(response_text: str, context: Optional[str] = None) -> None:
    """CLI command to suggest payloads based on response analysis."""
    engine = AdvancedPatternEngine()

    suggestions = engine.suggest_payloads(response_text, context)

    print(f"\n💡 Payload Suggestions ({len(suggestions)} suggestions)")
    print("=" * 60)

    for suggestion in suggestions:
        print(f"  • {suggestion}")


if __name__ == "__main__":
    # Demo usage
    engine = AdvancedPatternEngine()

    # Test text
    test_response = """
    <html>
    <body>
        <script>alert(1)</script>
        <input value="user_input_here">
        <div onload="prompt('xss')">Content</div>
    </body>
    </html>
    """

    print("🎯 XSS Vibes Advanced Pattern Engine Demo")
    print("=" * 50)

    matches = engine.match_patterns(test_response)
    print(f"\nFound {len(matches)} pattern matches:")

    for match in matches:
        print(f"  ✅ {match['pattern_name']} - {match['match_count']} matches")

    suggestions = engine.suggest_payloads(test_response)
    print(f"\nSuggested payload types: {', '.join(suggestions)}")
