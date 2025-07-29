#!/usr/bin/env python3
"""
XSS Vibes - GitHub Payload Extractor
Wyciąga payloady XSS z plików GitHub/źródeł HTML
"""
import re
import json
import html
from collections import defaultdict
import argparse


class GitHubPayloadExtractor:
    def __init__(self):
        self.patterns = {
            "postmessage_xss": [
                r'postMessage\s*\(\s*["\']([^"\']*(?:alert|eval|script|onerror)[^"\']*)["\']',
                r'window\.addEventListener\s*\(\s*["\']message["\'].*?\$\s*\(\s*event\.data\s*\)',
                r"onmessage\s*=.*?console\.log\s*\(\s*e\s*\)",
            ],
            "event_handlers": [
                r'<(?:img|svg|iframe|object)[^>]*(?:onerror|onload)=["\']([^"\']*)["\']',
                r"<svg[^>]*onload=([^>]+)>",
                r"<img[^>]*onerror=([^>]+)>",
            ],
            "dom_manipulation": [
                r'innerHTML\s*=\s*["\']([^"\']*)["\']',
                r'outerHTML\s*=\s*["\']([^"\']*)["\']',
                r'document\.write\s*\(\s*["\']([^"\']*)["\']',
            ],
            "template_injection": [
                r"\{\{([^}]*(?:alert|eval|script)[^}]*)\}\}",
                r"\[\[([^\]]*(?:alert|eval|script)[^\]]*)\]\]",
            ],
            "javascript_execution": [
                r'eval\s*\(\s*["\']([^"\']*)["\']',
                r'Function\s*\(\s*["\']([^"\']*)["\']',
                r'setTimeout\s*\(\s*["\']([^"\']*)["\']',
                r'setInterval\s*\(\s*["\']([^"\']*)["\']',
            ],
            "protocol_handlers": [
                r'javascript:([^"\']*)',
                r'data:text/html[^"\']*',
                r'vbscript:([^"\']*)',
            ],
        }

        self.extracted_payloads = defaultdict(list)

    def clean_payload(self, payload):
        """Czyści payload z HTML entities i zbędnych znaków"""
        # Decode HTML entities
        payload = html.unescape(payload)
        # Remove extra whitespace
        payload = " ".join(payload.split())
        # Remove quotes at start/end
        payload = payload.strip("\"'")
        return payload

    def extract_from_text(self, text):
        """Wyciąga payloady z tekstu"""
        payloads_found = 0

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    payload = (
                        match.group(1) if len(match.groups()) > 0 else match.group(0)
                    )
                    cleaned = self.clean_payload(payload)

                    if len(cleaned) > 3 and "alert" in cleaned.lower():
                        self.extracted_payloads[category].append(
                            {
                                "payload": cleaned,
                                "context": category,
                                "pattern": pattern,
                                "original": match.group(0),
                            }
                        )
                        payloads_found += 1

        return payloads_found

    def extract_specific_patterns(self, text):
        """Wyciąga specyficzne wzorce z GitHub HTML"""
        specific_patterns = {
            "postmessage_attack": r'postMessage\s*\(\s*["\']([^"\']*<[^>]*(?:onerror|onload)[^"\']*)["\']',
            "jquery_sink": r"\$\s*\(\s*event\.data\s*\)",
            "window_open": r'window\.open\s*\(\s*["\']([^"\']*)["\']',
            "svg_payload": r"<svg[^>]*onload\s*=\s*([^>]+)>",
            "img_payload": r"<img[^>]*onerror\s*=\s*([^>]+)>",
        }

        for name, pattern in specific_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) > 0:
                    payload = self.clean_payload(match.group(1))
                else:
                    payload = self.clean_payload(match.group(0))

                self.extracted_payloads["github_specific"].append(
                    {
                        "payload": payload,
                        "type": name,
                        "original": match.group(0),
                        "context": "github_html",
                    }
                )

    def generate_mutations(self, base_payload):
        """Generuje mutacje payloadu"""
        mutations = []

        # Basic encoding mutations
        mutations.append(base_payload.replace('"', "'"))
        mutations.append(base_payload.replace("'", '"'))

        # URL encoding
        mutations.append(base_payload.replace(" ", "%20"))
        mutations.append(base_payload.replace("<", "%3C").replace(">", "%3E"))

        # Case variations
        mutations.append(base_payload.upper())
        mutations.append(base_payload.lower())

        # Alternative event handlers
        if "onerror" in base_payload:
            mutations.append(base_payload.replace("onerror", "onload"))
            mutations.append(base_payload.replace("onerror", "onfocus"))

        if "alert" in base_payload:
            mutations.append(base_payload.replace("alert", "confirm"))
            mutations.append(base_payload.replace("alert", "prompt"))

        return mutations

    def export_to_json(self, filename="extracted_github_payloads.json"):
        """Eksportuje wyciągnięte payloady do JSON"""
        result = {
            "metadata": {
                "total_categories": len(self.extracted_payloads),
                "total_payloads": sum(
                    len(payloads) for payloads in self.extracted_payloads.values()
                ),
                "extraction_source": "github_html_analysis",
            },
            "categories": {},
        }

        for category, payloads in self.extracted_payloads.items():
            result["categories"][category] = {
                "count": len(payloads),
                "payloads": payloads,
            }

            # Add mutations for top payloads
            for payload_data in payloads[:3]:  # Top 3 per category
                mutations = self.generate_mutations(payload_data["payload"])
                payload_data["mutations"] = mutations[:5]  # Top 5 mutations

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return filename

    def print_summary(self):
        """Wyświetla podsumowanie"""
        print("🔥 GITHUB PAYLOAD EXTRACTION RESULTS 🔥")
        print("=" * 50)

        total_payloads = sum(
            len(payloads) for payloads in self.extracted_payloads.values()
        )
        print(f"📊 Total Categories: {len(self.extracted_payloads)}")
        print(f"📊 Total Payloads: {total_payloads}")
        print()

        for category, payloads in self.extracted_payloads.items():
            print(f"🎯 {category.upper()}: {len(payloads)} payloads")
            for i, payload_data in enumerate(payloads[:3]):
                print(f"  {i+1}. {payload_data['payload'][:60]}...")
            if len(payloads) > 3:
                print(f"  ... and {len(payloads) - 3} more")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="Extract XSS payloads from GitHub HTML"
    )
    parser.add_argument("input_file", help="Input file to analyze")
    parser.add_argument(
        "--output",
        "-o",
        default="extracted_github_payloads.json",
        help="Output JSON file",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    extractor = GitHubPayloadExtractor()

    # Read input file
    try:
        with open(args.input_file, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return 1

    # Extract payloads
    print(f"🔍 Analyzing {args.input_file}...")
    payloads_found = extractor.extract_from_text(content)
    extractor.extract_specific_patterns(content)

    # Export results
    output_file = extractor.export_to_json(args.output)
    print(f"💾 Results saved to: {output_file}")

    # Print summary
    if args.verbose:
        extractor.print_summary()
    else:
        total_payloads = sum(
            len(payloads) for payloads in extractor.extracted_payloads.values()
        )
        print(
            f"✅ Extracted {total_payloads} payloads from {len(extractor.extracted_payloads)} categories"
        )

    return 0


if __name__ == "__main__":
    exit(main())
