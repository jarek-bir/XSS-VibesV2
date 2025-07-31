#!/usr/bin/env python3
"""
XSS Vibes - Enhanced Advanced DPE Generator with CI/CD Support
Generates comprehensive DOM Parameter Exploitation templates for modern web security testing
"""

import os
import json
import argparse
from pathlib import Path


class EnhancedDPEGenerator:
    def __init__(self):
        self.templates = {
            "iframe_sandbox": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>Iframe Sandbox - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Iframe Sandbox Bypass Test</h2>
    
    <!-- Different sandbox configurations for testing -->
    <iframe id="frame1" sandbox="allow-scripts" srcdoc="&lt;script&gt;{{PAYLOAD}}&lt;/script&gt;"></iframe>
    <iframe id="frame2" sandbox="allow-same-origin allow-scripts" src="data:text/html,&lt;script&gt;{{PAYLOAD}}&lt;/script&gt;"></iframe>
    <iframe id="frame3" sandbox srcdoc="{{PAYLOAD}}"></iframe>
    
    <div id="output"></div>
    
    <script>
        // Try to inject into iframe contexts
        var payload = "{{PAYLOAD}}";
        
        // Method 1: Direct srcdoc manipulation
        document.getElementById('frame1').srcdoc = "<script>" + payload + "</script>";
        
        // Method 2: Data URL injection
        var dataUrl = "data:text/html," + encodeURIComponent("<script>" + payload + "</script>");
        document.getElementById('frame2').src = dataUrl;
        
        // Method 3: Sandbox attribute manipulation
        var frame3 = document.getElementById('frame3');
        frame3.setAttribute('sandbox', 'allow-scripts');
        frame3.srcdoc = payload;
        
        // Method 4: postMessage injection
        window.addEventListener('message', function(e) {
            document.getElementById('output').innerHTML = e.data;
        });
        
        // Try to send payload via postMessage
        setTimeout(() => {
            frames[0].postMessage(payload, '*');
        }, 100);
    </script>
</body>
</html>""",
                "contexts": [
                    "iframe.srcdoc",
                    "iframe.src data URL",
                    "sandbox bypass",
                    "postMessage injection",
                ],
            },
            "react_binding": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>React Data Binding - DPE Test</title>
    <meta charset="utf-8">
    <script crossorigin src="https://unpkg.com/react@17/umd/react.development.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
</head>
<body>
    <h2>React Data Binding XSS Test</h2>
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect } = React;
        
        function App() {
            const [userInput, setUserInput] = useState("{{PAYLOAD}}");
            const [dangerousHTML, setDangerousHTML] = useState("{{PAYLOAD}}");
            
            // Vulnerable: Direct JSX injection
            const VulnerableComponent = () => {
                return React.createElement('div', {
                    dangerouslySetInnerHTML: { __html: dangerousHTML }
                });
            };
            
            // Vulnerable: eval in useEffect
            useEffect(() => {
                try {
                    eval("console.log('" + userInput + "');");
                } catch (e) {}
            }, [userInput]);
            
            return React.createElement('div', null,
                React.createElement('h3', null, 'User Input: ' + userInput),
                React.createElement(VulnerableComponent)
            );
        }
        
        ReactDOM.render(React.createElement(App), document.getElementById('root'));
    </script>
</body>
</html>""",
                "contexts": [
                    "dangerouslySetInnerHTML",
                    "eval in useEffect",
                    "JSX injection",
                    "React DOM",
                ],
            },
            "web_components": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>Web Components - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Web Components XSS Test</h2>
    
    <custom-element data-payload="{{PAYLOAD}}"></custom-element>
    <shadow-element>{{PAYLOAD}}</shadow-element>
    
    <script>
        // Custom Element with vulnerabilities
        class CustomElement extends HTMLElement {
            connectedCallback() {
                const payload = this.getAttribute('data-payload');
                
                // Vulnerable: Direct innerHTML
                this.innerHTML = payload;
                
                // Vulnerable: Shadow DOM injection
                const shadow = this.attachShadow({mode: 'open'});
                shadow.innerHTML = '<style>:host { color: red; }</style>' + payload;
            }
        }
        
        customElements.define('custom-element', CustomElement);
        
        // Shadow DOM element
        class ShadowElement extends HTMLElement {
            constructor() {
                super();
                const shadow = this.attachShadow({mode: 'open'});
                const payload = this.textContent;
                shadow.innerHTML = payload;
            }
        }
        
        customElements.define('shadow-element', ShadowElement);
    </script>
</body>
</html>""",
                "contexts": [
                    "Custom element innerHTML",
                    "Shadow DOM injection",
                    "Attribute observers",
                ],
            },
            "jsonp": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>JSONP - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>JSONP XSS Test</h2>
    <div id="output"></div>
    
    <script>
        var payload = "{{PAYLOAD}}";
        
        // Vulnerable: Direct callback execution
        function jsonpCallback(data) {
            document.getElementById('output').innerHTML = data.message;
        }
        
        // Method 1: Direct script injection via JSONP
        var script1 = document.createElement('script');
        script1.src = 'data:text/javascript,jsonpCallback({"message":"' + payload + '"})';
        document.head.appendChild(script1);
        
        // Method 2: JSONP with eval
        function executeJsonp(response) {
            eval('var result = ' + response + '; jsonpCallback(result);');
        }
        
        executeJsonp('{"message":"' + payload + '"}');
    </script>
</body>
</html>""",
                "contexts": [
                    "JSONP callback execution",
                    "Script src injection",
                    "eval with JSONP",
                ],
            },
            "service_worker": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>Service Worker - DPE Test</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Service Worker XSS Test</h2>
    <div id="output"></div>
    
    <script>
        var payload = "{{PAYLOAD}}";
        
        // Service Worker registration with payload
        if ('serviceWorker' in navigator) {
            var swScript = `
                self.addEventListener('fetch', function(event) {
                    if (event.request.url.includes('xss-test')) {
                        event.respondWith(
                            new Response('<script>${payload}</script>', {
                                headers: {'Content-Type': 'text/html'}
                            })
                        );
                    }
                });
            `;
            
            var blob = new Blob([swScript], {type: 'application/javascript'});
            var swUrl = URL.createObjectURL(blob);
            
            navigator.serviceWorker.register(swUrl).then(function(registration) {
                console.log('SW registered:', registration);
            }).catch(function(error) {
                console.log('SW registration failed:', error);
            });
        }
        
        // Fetch with service worker interception
        fetch('/xss-test?payload=' + encodeURIComponent(payload))
            .then(response => response.text())
            .then(html => {
                document.getElementById('output').innerHTML = html;
            })
            .catch(err => console.log('Fetch error:', err));
    </script>
</body>
</html>""",
                "contexts": [
                    "Service worker script injection",
                    "Fetch interception",
                    "SW message handling",
                ],
            },
            "csp_blocked": {
                "html": """<!DOCTYPE html>
<html>
<head>
    <title>CSP Bypass - DPE Test</title>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; object-src 'none';">
</head>
<body>
    <h2>CSP Bypass Techniques Test</h2>
    <div id="output"></div>
    
    <script>
        var payload = "{{PAYLOAD}}";
        
        // Method 1: CSP bypass via iframe srcdoc
        var iframe = document.createElement('iframe');
        iframe.srcdoc = '<script>' + payload + '</script>';
        document.body.appendChild(iframe);
        
        // Method 2: CSP bypass via object data
        var object = document.createElement('object');
        object.data = 'data:text/html,' + encodeURIComponent('<script>' + payload + '</script>');
        document.body.appendChild(object);
        
        // Method 3: CSP bypass via base tag
        var base = document.createElement('base');
        base.href = 'data:text/html,';
        document.head.insertBefore(base, document.head.firstChild);
    </script>
</body>
</html>""",
                "contexts": [
                    "iframe srcdoc bypass",
                    "object data bypass",
                    "base tag manipulation",
                ],
            },
        }

    def list_templates(self):
        """List all available templates"""
        print("\n🎯 Enhanced Advanced DPE Templates:")
        print("=" * 50)
        for name, template in self.templates.items():
            contexts = template.get("contexts", [])
            print(f"\n📋 {name}:")
            print(f"   💡 Contexts: {len(contexts)}")
            for context in contexts:
                print(f"   • {context}")

    def generate_template(self, template_name, output_dir="test_templates"):
        """Generate a specific template"""
        if template_name not in self.templates:
            print(f"❌ Template '{template_name}' not found!")
            return

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        template = self.templates[template_name]

        # Generate HTML template
        html_file = output_path / f"{template_name}_template.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(template["html"])

        # Generate contexts JSON
        contexts_file = output_path / f"{template_name}_contexts.json"
        with open(contexts_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "template": template_name,
                    "contexts": template.get("contexts", []),
                    "description": f"Enhanced DPE template for {template_name} testing",
                },
                f,
                indent=2,
            )

        print(f"✅ Generated: {html_file}")
        print(f"✅ Generated: {contexts_file}")

    def generate_all(self, output_dir="test_templates"):
        """Generate all templates"""
        print(f"\n🚀 Generating all enhanced DPE templates to {output_dir}/")
        print("=" * 60)

        for template_name in self.templates:
            self.generate_template(template_name, output_dir)

        print(f"\n✅ Generated {len(self.templates)} enhanced DPE templates!")

    def create_cicd_script(self, output_dir="test_templates"):
        """Create CI/CD deployment script"""
        script_content = """#!/bin/bash
# XSS Vibes - Enhanced DPE CI/CD Deployment Script
# Usage: ./deploy_dpe_lab.sh [--output /var/www/html/xsslabs] [--docker]

set -e

OUTPUT_DIR="/var/www/html/xsslabs"
DOCKER_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --docker)
            DOCKER_MODE=true
            shift
            ;;
        --help|-h)
            echo "🔥 XSS Vibes - Enhanced DPE CI/CD Deployment"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --output DIR   Output directory (default: /var/www/html/xsslabs)"
            echo "  --docker       Generate Docker environment"
            echo "  --help         Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "🚀 XSS Vibes - Enhanced DPE Lab Deployment"
echo "=========================================="
echo "Output: $OUTPUT_DIR"
echo "Docker: $DOCKER_MODE"
echo ""

# Create output directory structure
mkdir -p "$OUTPUT_DIR"/{tests,reports,docker}

# Generate all templates with payloads
echo "📋 Generating test files..."
python3 ../scripts/enhanced_dpe_generator.py all --output "$OUTPUT_DIR"

# Create index page
cat > "$OUTPUT_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>XSS Vibes - Enhanced DPE Lab</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .template { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
        .test-links { margin-top: 10px; }
        .test-links a { margin-right: 10px; padding: 5px 10px; background: #007cba; color: white; text-decoration: none; }
    </style>
</head>
<body>
    <h1>🔥 XSS Vibes - Enhanced DPE Testing Lab</h1>
    <p>Advanced DOM Parameter Exploitation testing environment</p>
    
    <div class="template">
        <h3>📋 Iframe Sandbox Bypass</h3>
        <p>Tests iframe sandbox attribute bypasses and postMessage injection</p>
        <div class="test-links">
            <a href="iframe_sandbox_template.html">Template</a>
        </div>
    </div>
    
    <div class="template">
        <h3>📋 React Data Binding XSS</h3>
        <p>Tests React dangerouslySetInnerHTML and JSX injection vulnerabilities</p>
        <div class="test-links">
            <a href="react_binding_template.html">Template</a>
        </div>
    </div>
    
    <div class="template">
        <h3>📋 Web Components XSS</h3>
        <p>Tests Custom Elements, Shadow DOM, and slot injection</p>
        <div class="test-links">
            <a href="web_components_template.html">Template</a>
        </div>
    </div>
    
    <div class="template">
        <h3>📋 JSONP Injection</h3>
        <p>Tests JSONP callback manipulation and script injection</p>
        <div class="test-links">
            <a href="jsonp_template.html">Template</a>
        </div>
    </div>
    
    <div class="template">
        <h3>📋 Service Worker XSS</h3>
        <p>Tests Service Worker fetch interception and cache poisoning</p>
        <div class="test-links">
            <a href="service_worker_template.html">Template</a>
        </div>
    </div>
    
    <div class="template">
        <h3>📋 CSP Bypass Techniques</h3>
        <p>Tests various Content Security Policy bypass methods</p>
        <div class="test-links">
            <a href="csp_blocked_template.html">Template</a>
        </div>
    </div>
</body>
</html>
EOF

if [ "$DOCKER_MODE" = true ]; then
    echo "🐳 Generating Docker environment..."
    
    # Create Dockerfile
    cat > "$OUTPUT_DIR/docker/Dockerfile" << 'EOF'
FROM nginx:alpine

# Copy all test files
COPY ../ /usr/share/nginx/html/

# Custom nginx config for XSS testing
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    # Allow iframe embedding for testing \
    add_header X-Frame-Options "ALLOWALL" always; \
    \
    # Disable XSS protection for testing \
    add_header X-XSS-Protection "0" always; \
    \
    # Allow content sniffing for testing \
    add_header X-Content-Type-Options "" always; \
    \
    location / { \
        try_files $uri $uri/ =404; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
EOF

    # Create docker-compose.yml
    cat > "$OUTPUT_DIR/docker/docker-compose.yml" << 'EOF'
version: '3.8'
services:
  xss-dpe-lab:
    build: .
    ports:
      - "8080:80"
    volumes:
      - ..:/usr/share/nginx/html:ro
    environment:
      - NGINX_HOST=localhost
      - NGINX_PORT=80
    networks:
      - xss-lab-network

networks:
  xss-lab-network:
    driver: bridge
EOF

    echo "✅ Docker environment created!"
    echo "🚀 Run with: cd $OUTPUT_DIR/docker && docker-compose up"
fi

echo ""
echo "✅ Enhanced DPE Lab deployment complete!"
echo "🌐 Lab available at: $OUTPUT_DIR"
echo "📋 Index page: $OUTPUT_DIR/index.html"

if [ "$DOCKER_MODE" = false ]; then
    echo "🚀 Start HTTP server: cd $OUTPUT_DIR && python3 -m http.server 8080"
fi
"""

        script_file = Path(output_dir) / "deploy_dpe_lab.sh"
        with open(script_file, "w") as f:
            f.write(script_content)

        os.chmod(script_file, 0o755)
        print(f"✅ Created CI/CD deployment script: {script_file}")
        print("🚀 Features: Full lab deployment, Docker support, automated setup")


def main():
    parser = argparse.ArgumentParser(description="XSS Vibes Enhanced DPE Generator")
    parser.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=[
            "list",
            "all",
            "iframe_sandbox",
            "react_binding",
            "web_components",
            "jsonp",
            "service_worker",
            "csp_blocked",
        ],
        help="Action: template_name, list, or all",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="test_templates",
        help="Output directory (default: test_templates)",
    )
    parser.add_argument(
        "--script", action="store_true", help="Also create CI/CD deployment script"
    )

    args = parser.parse_args()
    generator = EnhancedDPEGenerator()

    print("🔥 XSS Vibes - Enhanced DPE Generator")
    print("=" * 50)

    if args.action == "list":
        generator.list_templates()
    elif args.action == "all":
        generator.generate_all(args.output)
        if args.script:
            generator.create_cicd_script(args.output)
    elif args.action in generator.templates:
        generator.generate_template(args.action, args.output)
        if args.script:
            generator.create_cicd_script(args.output)
    else:
        print(f"❌ Unknown action: {args.action}")
        generator.list_templates()


if __name__ == "__main__":
    main()
