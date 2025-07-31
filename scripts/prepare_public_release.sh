#!/bin/bash
# 🔥💀 XSS Vibes V2 - Public Release Preparation
# Tworzy czystą wersję bez naszych crown jewels

echo "🔥💀 Preparing XSS Vibes V2 for public release..."
echo "Removing sensitive crown jewels..."

# Create public directory
mkdir -p ../xss_vibes_public
cd ../xss_vibes_public

# Copy basic structure
cp -r ../xss_vibes/xss_vibes ./
cp ../xss_vibes/README.md ./
cp ../xss_vibes/requirements.txt ./
cp ../xss_vibes/setup.py ./

# Clean up sensitive files
echo "🧹 Cleaning sensitive files..."

# Remove crown jewel files
rm -f elite_payloads.py
rm -f advanced_payloads.py  
rm -f god_tier_encoded_matrix.json
rm -f no-experience-required-xss-signatures-only-fools-dont-use.txt
rm -f All_Payloads.txt
rm -f knoxss_config.json
rm -f waf_list.txt
rm -f waf_payloads.json

# Remove sensitive directories
rm -rf ultimate_hunt_*
rm -rf ctrip_specialized_hunt
rm -rf soa2_mass_hunt
rm -rf enhanced_xss_hunting_results
rm -rf dev_hunt_results
rm -rf test_api_hunt
rm -rf tools/automation

# Replace enhanced modules with basic versions
echo "📝 Creating public versions of modules..."

# Basic API hunter (without our enhancements)
cat > xss_vibes/api_hunter.py << 'EOL'
#!/usr/bin/env python3
"""
XSS Vibes V2 - Basic API Endpoint Hunter
Public version - basic API discovery functionality
"""

import asyncio
import aiohttp
import json
from typing import List, Dict

class APIEndpointHunter:
    def __init__(self):
        self.basic_patterns = [
            "/api/",
            "/api/v1/", 
            "/rest/",
            "/json/",
            "/ajax/"
        ]
    
    def generate_basic_targets(self, domain: str) -> List[str]:
        """Generate basic API targets"""
        targets = []
        for pattern in self.basic_patterns:
            targets.append(f"https://{domain}{pattern}")
        return targets
    
    async def basic_hunt(self, domains: List[str]):
        """Basic API hunting - public version"""
        print("🔍 Basic API discovery...")
        # Basic implementation without crown jewels
        pass
EOL

# Basic payload manager (without advanced payloads)
cat > xss_vibes/payload_manager.py << 'EOL'
#!/usr/bin/env python3
"""
XSS Vibes V2 - Basic Payload Manager
Public version - basic XSS payloads only
"""

class BasicPayloadManager:
    def __init__(self):
        self.basic_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>"
        ]
    
    def get_basic_payloads(self):
        """Get basic XSS payloads"""
        return self.basic_payloads
EOL

echo "✅ Public version ready in ../xss_vibes_public"
echo "🔒 Crown jewels safely kept private!"
echo ""
echo "📋 What's excluded from public:"
echo "  - Advanced payload matrices"
echo "  - Fingerprint token analysis" 
echo "  - Token replay techniques"
echo "  - WAF evasion signatures"
echo "  - Mega scale automation"
echo "  - Premium hunt results"
echo "  - Business integrations"
echo ""
echo "🎯 Public gets: Basic framework, standard payloads, educational content"
