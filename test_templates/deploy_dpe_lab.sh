#!/bin/bash
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
RUN echo 'server {     listen 80;     server_name localhost;     root /usr/share/nginx/html;     index index.html;         # Allow iframe embedding for testing     add_header X-Frame-Options "ALLOWALL" always;         # Disable XSS protection for testing     add_header X-XSS-Protection "0" always;         # Allow content sniffing for testing     add_header X-Content-Type-Options "" always;         location / {         try_files $uri $uri/ =404;     } }' > /etc/nginx/conf.d/default.conf

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
