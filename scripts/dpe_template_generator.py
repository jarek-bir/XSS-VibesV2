#!/usr/bin/env python3
"""
XSS Vibes - DPE Template Generator
Generates DOM templates for DPE (DOM-based Parameter Exploitation) fuzzing
"""

import os
import json
import argparse
from pathlib import Path


class DPETemplateGenerator:
    def __init__(self):
        self.templates = {
            "login_form": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>Login Form - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Login Form Test</h2>
    <form method="post" action="/login" id="loginForm">
        <div>
            <label>Username:</label>
            <input type="text" name="username" value="{{PAYLOAD}}" id="username" />
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" value="test123" />
        </div>
        <button type="submit">Login</button>
    </form>
    
    <div id="welcome"></div>
    <div id="debug"></div>
    
    <script>
        // Multiple injection contexts for comprehensive testing
        var username = "{{PAYLOAD}}";
        var userData = {
            name: "{{PAYLOAD}}",
            role: "user"
        };
        
        // DOM manipulation sink
        if (username) {
            document.getElementById('welcome').innerHTML = "Hello " + username;
        }
        
        // Eval sink
        try {
            eval("var userRole = '" + username + "';");
            document.getElementById('debug').innerText = "Role: " + userRole;
        } catch(e) {
            document.getElementById('debug').innerText = "Error: " + e.message;
        }
        
        // Event handler sink
        document.getElementById('username').setAttribute('onerror', '{{PAYLOAD}}');
        
        // setTimeout sink
        setTimeout("console.log('User: {{PAYLOAD}}')", 100);
    </script>
</body>
</html>""",
                "contexts": [
                    "attribute_value",
                    "js_string",
                    "dom_innerHTML",
                    "eval_context",
                    "event_handler",
                    "setTimeout",
                ],
                "description": "Login form with multiple XSS injection points",
            },
            "search_form": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>Search Form - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Search Interface</h2>
    <form method="get" action="/search">
        <input type="text" name="q" value="{{PAYLOAD}}" placeholder="Search..." id="searchInput" />
        <button type="submit">Search</button>
    </form>
    
    <div id="results"></div>
    <div id="searchInfo"></div>
    
    <script>
        var query = decodeURIComponent("{{PAYLOAD}}");
        var searchData = `Search term: {{PAYLOAD}}`;
        
        // Document title injection
        document.title = "Search: " + query;
        
        // Template literal injection
        document.getElementById('searchInfo').innerHTML = searchData;
        
        // URL parameter injection
        var url = "/api/search?q={{PAYLOAD}}";
        
        // Eval injection
        eval("var searchTerm = '" + query + "';");
        
        // JSON injection
        var apiPayload = JSON.stringify({
            "query": "{{PAYLOAD}}",
            "type": "fuzzing"
        });
        
        // Document.write injection
        document.write("<div>Searching for: {{PAYLOAD}}</div>");
        
        // Location.href injection
        // location.href = "javascript:alert('Search: {{PAYLOAD}}')";
    </script>
</body>
</html>""",
                "contexts": [
                    "attribute_value",
                    "js_string",
                    "template_literal",
                    "document_title",
                    "eval_context",
                    "json_value",
                    "document_write",
                    "javascript_protocol",
                ],
                "description": "Search form with URL parameters and JSON API testing",
            },
            "json_api": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>JSON API - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>JSON API Test</h2>
    <div id="output"></div>
    <div id="apiResult"></div>
    
    <script>
        // JSON API payload injection
        var apiData = {
            "user": "{{PAYLOAD}}",
            "role": "admin",
            "settings": {
                "theme": "{{PAYLOAD}}",
                "language": "en"
            }
        };
        
        // Fetch API injection
        fetch('/api/user', {
            method: 'POST',
            body: JSON.stringify(apiData),
            headers: {'Content-Type': 'application/json'}
        }).then(response => response.text())
        .then(data => {
            // Response handling injection
            document.getElementById('apiResult').innerHTML = "Response: {{PAYLOAD}}";
        }).catch(error => {
            console.error('API Error:', error);
        });
        
        // WebSocket injection
        var wsData = JSON.stringify({
            "action": "subscribe",
            "channel": "{{PAYLOAD}}"
        });
        
        // LocalStorage injection
        localStorage.setItem('user', '{{PAYLOAD}}');
        var storedUser = localStorage.getItem('user');
        document.getElementById('output').innerHTML = "Stored: " + storedUser;
        
        // PostMessage injection
        window.postMessage({
            "type": "userUpdate",
            "data": "{{PAYLOAD}}"
        }, "*");
        
        // Cookie injection
        document.cookie = "user={{PAYLOAD}}; path=/";
    </script>
</body>
</html>""",
                "contexts": [
                    "json_value",
                    "fetch_body",
                    "dom_innerHTML",
                    "localStorage",
                    "postMessage",
                    "cookie_value",
                ],
                "description": "JSON API with modern web technologies",
            },
            "dom_sinks": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>DOM Sinks - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>DOM Sinks Comprehensive Test</h2>
    <div id="output"></div>
    <div id="results"></div>
    
    <script>
        var payload = "{{PAYLOAD}}";
        
        // innerHTML sink
        document.getElementById('output').innerHTML = payload;
        
        // outerHTML sink
        document.getElementById('results').outerHTML = "<div id='results'>" + payload + "</div>";
        
        // document.write sink
        document.write("<p>Document write: " + payload + "</p>");
        
        // insertAdjacentHTML sink
        document.body.insertAdjacentHTML('beforeend', "<div>Adjacent: " + payload + "</div>");
        
        // eval sink
        eval("var testVar = '" + payload + "';");
        
        // Function constructor sink
        new Function("return '" + payload + "'")();
        
        // setTimeout string sink
        setTimeout("console.log('Timeout: {{PAYLOAD}}')", 100);
        
        // setInterval string sink
        setInterval("console.log('Interval: {{PAYLOAD}}')", 1000);
        
        // location sinks
        // location.href = "javascript:" + payload;
        // location.assign("javascript:" + payload);
        
        // window.open sink
        // window.open("javascript:" + payload);
        
        // Script element injection
        var script = document.createElement('script');
        script.textContent = "console.log('Script: {{PAYLOAD}}')";
        document.head.appendChild(script);
        
        // CSS injection
        var style = document.createElement('style');
        style.textContent = "body { background-image: url('{{PAYLOAD}}'); }";
        document.head.appendChild(style);
        
        // Range API sink
        var range = document.createRange();
        range.createContextualFragment("<div>Range: " + payload + "</div>");
    </script>
</body>
</html>""",
                "contexts": [
                    "innerHTML",
                    "outerHTML",
                    "document_write",
                    "insertAdjacentHTML",
                    "eval",
                    "function_constructor",
                    "setTimeout",
                    "setInterval",
                    "javascript_protocol",
                    "script_element",
                    "css_injection",
                    "range_api",
                ],
                "description": "Comprehensive DOM sinks testing",
            },
            "spa_framework": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>SPA Framework - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Single Page Application Test</h2>
    <div id="app"></div>
    <div id="router"></div>
    
    <script>
        // Simulated SPA framework patterns
        var appState = {
            user: {
                name: "{{PAYLOAD}}",
                bio: "{{PAYLOAD}}"
            },
            route: "{{PAYLOAD}}"
        };
        
        // Template rendering (Vue.js style)
        var template = `
            <div class="user-profile">
                <h3>{{PAYLOAD}}</h3>
                <p>Bio: {{PAYLOAD}}</p>
            </div>
        `;
        document.getElementById('app').innerHTML = template;
        
        // Router injection (React Router style)
        var route = "{{PAYLOAD}}";
        history.pushState({}, "", route);
        
        // Component props injection
        var component = {
            props: {
                title: "{{PAYLOAD}}",
                content: "{{PAYLOAD}}"
            },
            render: function() {
                return "<div><h4>" + this.props.title + "</h4><p>" + this.props.content + "</p></div>";
            }
        };
        
        // Virtual DOM injection
        var vdom = {
            type: "div",
            props: {
                dangerouslySetInnerHTML: {
                    __html: "{{PAYLOAD}}"
                }
            }
        };
        
        // Event listener injection
        document.addEventListener('custom-event', function(e) {
            console.log('Custom event data:', e.detail);
            document.getElementById('router').innerHTML = "Event: " + e.detail;
        });
        
        // Dispatch custom event with payload
        var customEvent = new CustomEvent('custom-event', {
            detail: "{{PAYLOAD}}"
        });
        document.dispatchEvent(customEvent);
        
        // Module import simulation
        var moduleCode = `
            export function processData() {
                return "{{PAYLOAD}}";
            }
        `;
    </script>
</body>
</html>""",
                "contexts": [
                    "template_rendering",
                    "router_injection",
                    "component_props",
                    "virtual_dom",
                    "event_listener",
                    "custom_event",
                    "module_code",
                ],
                "description": "Modern SPA framework patterns testing",
            },
        }

    def generate_template(self, template_name, output_dir="test_templates"):
        """Generate DPE fuzzing template"""
        if template_name not in self.templates:
            print(f"❌ Template '{template_name}' not found!")
            return False

        template = self.templates[template_name]

        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)

        # Save HTML template
        html_file = Path(output_dir) / f"{template_name}_template.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(template["html"])

        # Save context info
        context_file = Path(output_dir) / f"{template_name}_contexts.json"
        context_data = {
            "template": template_name,
            "contexts": template["contexts"],
            "payload_marker": "{{PAYLOAD}}",
            "description": template["description"],
            "generated_at": "2025-07-29",
            "file": str(html_file),
        }

        with open(context_file, "w", encoding="utf-8") as f:
            json.dump(context_data, f, indent=2)

        print(f"✅ Generated template: {html_file}")
        print(f"✅ Generated contexts: {context_file}")
        print(
            f"📋 Available contexts ({len(template['contexts'])}): {', '.join(template['contexts'])}"
        )
        print(f"📄 Description: {template['description']}")
        return True

    def list_templates(self):
        """List all available templates"""
        print("🎯 Available DPE Templates:")
        print("=" * 50)
        for name, template in self.templates.items():
            print(f"📄 {name:<20} - {len(template['contexts'])} contexts")
            print(f"   └─ {template['description']}")
        print()
        print("💡 Usage: xss-dpe <template_name> or xss-dpe all")

    def generate_all(self, output_dir="test_templates"):
        """Generate all templates"""
        print("🚀 Generating all DPE templates...")
        print("=" * 50)
        success_count = 0

        for template_name in self.templates.keys():
            print(f"\n🔄 Generating {template_name}...")
            if self.generate_template(template_name, output_dir):
                success_count += 1

        print(
            f"\n🎉 Successfully generated {success_count}/{len(self.templates)} templates!"
        )
        print(f"📁 Templates saved in: {Path(output_dir).absolute()}")

    def create_fuzzing_script(self, output_dir="test_templates"):
        """Create a fuzzing script for the templates"""
        script_content = """#!/bin/bash
# XSS Vibes - DPE Fuzzing Script
# Usage: ./fuzz_templates.sh <template_name> <payload_file>

TEMPLATE_DIR="$(dirname "$0")"
PAYLOAD_FILE="${2:-../xss_vibes/data/basic_xss.json}"

if [ -z "$1" ]; then
    echo "🎯 DPE Fuzzing Script"
    echo "Usage: $0 <template_name> [payload_file]"
    echo ""
    echo "Available templates:"
    ls -1 "$TEMPLATE_DIR"/*_template.html | sed 's/_template.html$//' | sed 's/.*\\///' | sed 's/^/  • /'
    exit 1
fi

TEMPLATE_NAME="$1"
TEMPLATE_FILE="$TEMPLATE_DIR/${TEMPLATE_NAME}_template.html"

if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "❌ Template not found: $TEMPLATE_FILE"
    exit 1
fi

echo "🔥 Starting DPE fuzzing for: $TEMPLATE_NAME"
echo "📄 Template: $TEMPLATE_FILE"
echo "💣 Payloads: $PAYLOAD_FILE"
echo ""

# Extract payloads from JSON
if [ -f "$PAYLOAD_FILE" ]; then
    PAYLOADS=$(python3 -c "
import json
with open('$PAYLOAD_FILE') as f:
    data = json.load(f)
    if isinstance(data, list):
        for item in data[:10]:  # Limit to first 10
            if isinstance(item, dict) and 'payload' in item:
                print(item['payload'])
            elif isinstance(item, str):
                print(item)
    elif isinstance(data, dict) and 'payloads' in data:
        for payload in data['payloads'][:10]:
            print(payload)
")
else
    # Default payloads if file not found
    PAYLOADS="<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(1)
';alert(1);//
\">alert(1)</script>"
fi

COUNTER=1
echo "$PAYLOADS" | while read -r payload; do
    if [ -n "$payload" ]; then
        OUTPUT_FILE="$TEMPLATE_DIR/test_${TEMPLATE_NAME}_${COUNTER}.html"
        
        # Replace {{PAYLOAD}} with actual payload
        sed "s/{{PAYLOAD}}/${payload//\\//\\\\}/g" "$TEMPLATE_FILE" > "$OUTPUT_FILE"
        
        echo "📋 Test $COUNTER: $OUTPUT_FILE"
        echo "   Payload: ${payload:0:50}..."
        
        ((COUNTER++))
    fi
done

echo ""
echo "✅ DPE fuzzing complete!"
echo "🌐 Open generated HTML files in browser to test"
"""

        script_file = Path(output_dir) / "fuzz_templates.sh"
        with open(script_file, "w") as f:
            f.write(script_content)

        os.chmod(script_file, 0o755)
        print(f"✅ Created fuzzing script: {script_file}")


def main():
    parser = argparse.ArgumentParser(description="XSS Vibes DPE Template Generator")
    parser.add_argument(
        "action", nargs="?", default="list", help="Action: template_name, list, or all"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="test_templates",
        help="Output directory (default: test_templates)",
    )
    parser.add_argument(
        "--script", action="store_true", help="Also create fuzzing script"
    )

    args = parser.parse_args()
    generator = DPETemplateGenerator()

    print("🔥 XSS Vibes - DPE Template Generator")
    print("=" * 50)

    if args.action == "list":
        generator.list_templates()
    elif args.action == "all":
        generator.generate_all(args.output)
        if args.script:
            generator.create_fuzzing_script(args.output)
    elif args.action in generator.templates:
        generator.generate_template(args.action, args.output)
        if args.script:
            generator.create_fuzzing_script(args.output)
    else:
        print(f"❌ Unknown action: {args.action}")
        generator.list_templates()


if __name__ == "__main__":
    main()
