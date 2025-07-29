#!/usr/bin/env python3
"""
XSS Vibes - GitHub Payload Integrator
Integruje prawdziwe payloady z GitHub do systemu XSS Vibes
"""
import json
import os
from datetime import datetime


def integrate_github_payloads():
    """Integruje GitHub payloady do systemu XSS Vibes"""

    # Ścieżki plików
    github_file = "github_real_world_payloads.json"
    data_dir = "xss_vibes/data"

    # Wczytaj GitHub payloady
    with open(github_file, "r") as f:
        github_data = json.load(f)

    # Utwórz nowe pliki kategorii
    for category, data in github_data["categories"].items():
        category_file = os.path.join(data_dir, "categories", f"{category}.json")

        category_data = {
            "metadata": {
                "name": data["description"],
                "priority": data["priority"],
                "source": "GitHub Real-world Analysis",
                "extraction_date": datetime.now().isoformat(),
                "total_payloads": len(data["payloads"]),
            },
            "payloads": [],
        }

        # Konwertuj payloady do formatu XSS Vibes
        for payload_data in data["payloads"]:
            xss_payload = {
                "payload": payload_data["payload"],
                "context": payload_data["context"],
                "method": payload_data["method"],
                "priority": data["priority"],
                "source": "github_analysis",
                "mutations": payload_data.get("mutations", []),
                "metadata": {
                    "real_world": True,
                    "tested": True,
                    "effectiveness": "high",
                },
            }
            category_data["payloads"].append(xss_payload)

        # Zapisz kategorię
        os.makedirs(os.path.dirname(category_file), exist_ok=True)
        with open(category_file, "w") as f:
            json.dump(category_data, f, indent=2)

        print(f"✅ Created {category_file} with {len(data['payloads'])} payloads")

    # Utwórz nowy plik do zarządzania kategoriami GitHub
    github_categories_file = os.path.join(data_dir, "github_categories.json")

    github_categories_data = {
        "metadata": {
            "name": "GitHub Real-world XSS Payloads",
            "description": "Categories extracted from real GitHub HTML analysis",
            "last_updated": datetime.now().isoformat(),
            "total_categories": len(github_data["categories"]),
            "total_payloads": github_data["metadata"]["total_payloads"],
            "source": "github_html_analysis",
        },
        "categories": {},
    }

    # Dodaj GitHub kategorie
    for category, data in github_data["categories"].items():
        github_categories_data["categories"][category] = {
            "file": f"categories/{category}.json",
            "priority": data["priority"],
            "payload_count": len(data["payloads"]),
            "source": "github_analysis",
            "description": data["description"],
        }

    with open(github_categories_file, "w") as f:
        json.dump(github_categories_data, f, indent=2)

    print(f"✅ Created {github_categories_file}")

    # Utwórz summary report
    summary = {
        "integration_date": datetime.now().isoformat(),
        "source_file": github_file,
        "categories_added": len(github_data["categories"]),
        "total_payloads_added": github_data["metadata"]["total_payloads"],
        "categories": list(github_data["categories"].keys()),
        "priority_distribution": {
            category: data["priority"]
            for category, data in github_data["categories"].items()
        },
    }

    with open("github_integration_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"✅ Created integration summary: github_integration_summary.json")

    return summary


if __name__ == "__main__":
    print("🔥 XSS Vibes - GitHub Payload Integration 🔥")
    print("=" * 50)

    summary = integrate_github_payloads()

    print()
    print("📊 INTEGRATION SUMMARY:")
    print(f"  Categories Added: {summary['categories_added']}")
    print(f"  Total Payloads: {summary['total_payloads_added']}")
    print(f"  Source: Real GitHub HTML Analysis")
    print()

    print("🎯 CATEGORIES:")
    for category in summary["categories"]:
        priority = summary["priority_distribution"][category]
        print(f"  • {category} (priority: {priority})")

    print()
    print("✅ GitHub payloads successfully integrated into XSS Vibes!")
    print("🚀 Ready for AI-powered testing with real-world patterns!")
