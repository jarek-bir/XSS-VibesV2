#!/usr/bin/env python3
"""
XSS Vibes V2 - API Endpoint Hunter
Specialized module for discovering and analyzing API endpoints
"""

import asyncio
import aiohttp
import json
import re
import time
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse
import logging
from pathlib import Path


class APIEndpointHunter:
    def __init__(self):
        self.api_patterns = self.load_api_patterns()
        self.setup_logging()
        self.session = None
        self.discovered_apis = []

    def setup_logging(self):
        """Setup logging for API hunter"""
        self.logger = logging.getLogger("APIHunter")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def load_api_patterns(self) -> Dict:
        """Load patterns for detecting API endpoints"""
        return {
            "api_paths": [
                # REST API patterns
                "/api/",
                "/api/v1/",
                "/api/v2/",
                "/api/v3/",
                "/rest/",
                "/restapi/",
                "/rest-api/",
                "/graphql/",
                "/graphql",
                "/gql/",
                "/json/",
                "/xml/",
                "/ajax/",
                # Framework specific
                "/wp-json/",
                "/wp-admin/admin-ajax.php",
                "/drupal/",
                "/joomla/",
                "/laravel/api/",
                "/symfony/api/",
                # Mobile APIs
                "/mobile/",
                "/m/api/",
                "/app/api/",
                "/ios/",
                "/android/",
                "/mobile-api/",
                # SOA patterns (like Ctrip)
                "/soa/",
                "/soa2/",
                "/restapi/soa2/",
                "/restapi/soa2/11470/",
                "/restapi/soa2/18088/",
                "/restapi/soa2/12345/",
                "/restapi/soa2/67890/",
                "/service/",
                "/rpc/",
                "/soap/",
                "/wsdl/",
                # Microservices
                "/microservice/",
                "/ms/",
                "/services/",
                "/gateway/",
                "/proxy/",
                # Internal APIs
                "/internal/",
                "/private/",
                "/admin/api/",
                "/dev/api/",
                "/test/api/",
                "/staging/api/",
                # Cloud APIs
                "/aws/",
                "/azure/",
                "/gcp/",
                "/cloud/",
                # Authentication
                "/auth/",
                "/oauth/",
                "/token/",
                "/login/api/",
                "/sso/",
                "/saml/",
                "/openid/",
                # Data APIs
                "/data/",
                "/export/",
                "/import/",
                "/sync/",
                "/backup/",
                "/restore/",
                "/dump/",
            ],
            "api_files": [
                # JSON endpoints
                "api.json",
                "config.json",
                "settings.json",
                "manifest.json",
                "data.json",
                "users.json",
                "products.json",
                "orders.json",
                "getToken.json",
                "getConfig.json",
                "getUser.json",
                "getAppConfig.json",
                "getSettings.json",
                # XML endpoints
                "api.xml",
                "config.xml",
                "sitemap.xml",
                "feed.xml",
                "soap.xml",
                "wsdl.xml",
                "rss.xml",
                # PHP endpoints
                "api.php",
                "ajax.php",
                "service.php",
                "endpoint.php",
                "rest.php",
                "json.php",
                "xml.php",
                # ASP endpoints
                "api.asp",
                "api.aspx",
                "service.asmx",
                "ajax.ashx",
                "webservice.asmx",
                "wcf.svc",
                # JSP endpoints
                "api.jsp",
                "service.jsp",
                "rest.jsp",
                "ajax.jsp",
                # Node.js endpoints
                "api.js",
                "service.js",
                "endpoint.js",
                # Python endpoints
                "api.py",
                "service.py",
                "endpoint.py",
                # Other endpoints
                "api",
                "service",
                "endpoint",
                "gateway",
            ],
            "api_parameters": [
                # Common API parameters
                "action",
                "method",
                "function",
                "cmd",
                "command",
                "service",
                "operation",
                "call",
                "request",
                "format",
                "output",
                "type",
                "version",
                "callback",
                "jsonp",
                "token",
                "key",
                "apikey",
                "id",
                "uid",
                "user_id",
                "session_id",
                "limit",
                "offset",
                "page",
                "size",
                "count",
            ],
            "content_indicators": [
                # JSON response indicators
                r'"data"\s*:\s*{',
                r'"result"\s*:\s*{',
                r'"response"\s*:\s*{',
                r'"success"\s*:\s*(true|false)',
                r'"error"\s*:\s*',
                r'"message"\s*:\s*"',
                r'"code"\s*:\s*\d+',
                r'"status"\s*:\s*\d+',
                r'"token"\s*:\s*"',
                r'"apikey"\s*:\s*"',
                r'"sessionid"\s*:\s*"',
                # XML response indicators
                r"<\?xml\s+version=",
                r"<soap:Envelope",
                r"<response>",
                r"<result>",
                r"<data>",
                r"<error>",
                # Error messages (Chinese for Ctrip-like sites)
                r"请求体不能为空",
                r"必须为JSON格式",
                r"参数错误",
                r"token无效",
                r"权限不足",
                r"接口不存在",
                # Common API errors
                r"Invalid API key",
                r"Missing required parameter",
                r"Authentication failed",
                r"Rate limit exceeded",
                r"Method not allowed",
                r"Internal server error",
            ],
            "high_value_endpoints": [
                # Authentication & tokens
                "getToken",
                "generateToken",
                "refreshToken",
                "validateToken",
                "login",
                "logout",
                "authenticate",
                "authorize",
                "oauth",
                "sso",
                "saml",
                # User data
                "getUser",
                "getUserInfo",
                "getProfile",
                "getAccount",
                "users",
                "profiles",
                "accounts",
                "members",
                # Configuration
                "getConfig",
                "getSettings",
                "getAppConfig",
                "getSystemConfig",
                "config",
                "settings",
                "preferences",
                "options",
                # Financial/Payment
                "payment",
                "billing",
                "invoice",
                "transaction",
                "order",
                "wallet",
                "balance",
                "credit",
                "charge",
                # Administrative
                "admin",
                "management",
                "dashboard",
                "control",
                "system",
                "status",
                "health",
                "monitor",
                # Data access
                "export",
                "import",
                "backup",
                "restore",
                "dump",
                "data",
                "database",
                "sql",
                "query",
            ],
        }

    async def init_session(self):
        """Initialize aiohttp session"""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=15)
        timeout = aiohttp.ClientTimeout(total=20)
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
        }

        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        )

    async def close_session(self):
        """Close session"""
        if self.session:
            await self.session.close()

    def generate_api_targets(self, base_domain: str) -> List[str]:
        """Generate potential API targets from base domain"""
        targets = []
        parsed = urlparse(
            f"http://{base_domain}"
            if not base_domain.startswith("http")
            else base_domain
        )
        domain = parsed.netloc or parsed.path

        # Remove www if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Generate API subdomain variants
        api_subdomains = [
            "api",
            "api1",
            "api2",
            "api-v1",
            "api-v2",
            "m",
            "mobile",
            "app",
            "rest",
            "service",
            "gateway",
            "internal",
            "private",
            "admin-api",
        ]

        for subdomain in api_subdomains:
            targets.extend(
                [f"http://{subdomain}.{domain}", f"https://{subdomain}.{domain}"]
            )

        # Generate path variants for main domain and subdomains
        base_urls = [f"http://{domain}", f"https://{domain}"]
        if not domain.startswith("www."):
            base_urls.extend([f"http://www.{domain}", f"https://www.{domain}"])

        # Add mobile subdomain (like m.ctrip.com)
        base_urls.extend([f"http://m.{domain}", f"https://m.{domain}"])

        for base_url in base_urls:
            # Add API paths
            for path in self.api_patterns["api_paths"]:
                targets.append(f"{base_url}{path}")

            # Add API files
            for api_file in self.api_patterns["api_files"]:
                targets.append(f"{base_url}/{api_file}")
                # Also try in common directories
                for path in ["/api/", "/rest/", "/restapi/", "/mobile/", "/app/"]:
                    targets.append(f"{base_url}{path}{api_file}")

        return list(set(targets))  # Remove duplicates

    async def test_api_endpoint(self, url: str) -> Optional[Dict]:
        """Test API endpoint and analyze response"""
        try:
            # Test GET request first
            get_result = await self._test_http_method(url, "GET")

            # Test POST request if GET fails or indicates POST required
            post_result = None
            if get_result and (
                get_result.get("status_code") in [405, 400]
                or "请求体不能为空" in get_result.get("content", "")
                or "POST" in get_result.get("content", "")
            ):
                post_result = await self._test_http_method(url, "POST")

            # Analyze results
            best_result = (
                post_result if post_result and post_result.get("is_api") else get_result
            )

            if best_result and best_result.get("is_api"):
                return best_result

        except Exception as e:
            self.logger.debug(f"Error testing {url}: {e}")

        return None

    async def _test_http_method(self, url: str, method: str) -> Optional[Dict]:
        """Test specific HTTP method on endpoint"""
        try:
            kwargs = {}
            if method == "POST":
                # Try different POST payloads
                payloads = [
                    {},  # Empty JSON
                    {"test": "data"},  # Basic JSON
                    {"action": "test", "format": "json"},  # Common API params
                ]

                for payload in payloads:
                    kwargs["json"] = payload
                    result = await self._make_request(url, method, **kwargs)
                    if result and result.get("is_api"):
                        return result

                return None
            else:
                return await self._make_request(url, method, **kwargs)

        except Exception as e:
            self.logger.debug(f"Error with {method} {url}: {e}")
            return None

    async def _make_request(self, url: str, method: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request and analyze response"""
        if not self.session:
            await self.init_session()

        try:
            async with self.session.request(method, url, **kwargs) as response:
                content = await response.text()
                headers = dict(response.headers)

                # Analyze response
                analysis = {
                    "url": url,
                    "method": method,
                    "status_code": response.status,
                    "headers": headers,
                    "content": content[:2000],  # Limit content
                    "content_length": len(content),
                    "is_api": False,
                    "api_type": None,
                    "confidence": 0,
                    "indicators": [],
                    "data_extracted": {},
                    "risk_level": "LOW",
                }

                # Check if it's an API endpoint
                confidence = 0
                indicators = []

                # Check content type
                content_type = headers.get("content-type", "").lower()
                if "application/json" in content_type:
                    confidence += 30
                    indicators.append("JSON Content-Type")
                elif "application/xml" in content_type or "text/xml" in content_type:
                    confidence += 25
                    indicators.append("XML Content-Type")

                # Check content indicators
                for pattern in self.api_patterns["content_indicators"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        confidence += 15
                        indicators.append(f"Content pattern: {pattern[:30]}...")

                # Check URL patterns
                url_lower = url.lower()
                for high_value in self.api_patterns["high_value_endpoints"]:
                    if high_value.lower() in url_lower:
                        confidence += 20
                        indicators.append(f"High-value endpoint: {high_value}")
                        analysis["risk_level"] = "HIGH"

                # Check for API-like responses
                if response.status in [200, 400, 401, 403, 405]:
                    confidence += 10
                    indicators.append(f"API-like status: {response.status}")

                # Try to parse JSON
                try:
                    json_data = json.loads(content)
                    confidence += 25
                    indicators.append("Valid JSON response")
                    analysis["data_extracted"] = self._extract_sensitive_data(json_data)

                    # Determine API type
                    if "token" in json_data.get("data", {}):
                        analysis["api_type"] = "TOKEN_API"
                        analysis["risk_level"] = "HIGH"
                        confidence += 30
                    elif "config" in url_lower or "setting" in url_lower:
                        analysis["api_type"] = "CONFIG_API"
                        analysis["risk_level"] = "MEDIUM"
                        confidence += 20

                except json.JSONDecodeError:
                    pass

                # Check for error messages that indicate API
                api_errors = [
                    "请求体不能为空",
                    "JSON格式",
                    "Invalid API",
                    "Missing parameter",
                    "Authentication required",
                    "Access denied",
                    "Rate limit",
                ]
                for error in api_errors:
                    if error in content:
                        confidence += 15
                        indicators.append(f"API error message: {error}")

                # Final assessment
                analysis["confidence"] = min(confidence, 100)
                analysis["indicators"] = indicators
                analysis["is_api"] = confidence >= 30

                return analysis

        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            return None

    def _extract_sensitive_data(self, json_data: Dict) -> Dict:
        """Extract potentially sensitive data from JSON response"""
        sensitive_keys = [
            "token",
            "apikey",
            "api_key",
            "secret",
            "password",
            "pwd",
            "sessionid",
            "session_id",
            "cookie",
            "auth",
            "authorization",
            "key",
            "private",
            "config",
            "settings",
            "database",
            "db",
            "url",
            "endpoint",
            "host",
            "server",
            "path",
            "script",
        ]

        extracted = {}

        def extract_recursive(data, prefix=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = key.lower()
                    current_key = f"{prefix}.{key}" if prefix else key

                    if any(sensitive in key_lower for sensitive in sensitive_keys):
                        extracted[current_key] = value

                    if isinstance(value, (dict, list)):
                        extract_recursive(value, current_key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    if isinstance(item, (dict, list)):
                        extract_recursive(item, f"{prefix}[{i}]")

        extract_recursive(json_data)
        return extracted

    async def hunt_api_endpoints(
        self, domains: List[str], max_concurrent: int = 20
    ) -> List[Dict]:
        """Hunt for API endpoints across multiple domains"""
        await self.init_session()

        try:
            all_targets = []
            for domain in domains:
                targets = self.generate_api_targets(domain)
                all_targets.extend(targets)

            self.logger.info(
                f"🔍 Testing {len(all_targets)} potential API endpoints..."
            )

            # Test all targets concurrently
            semaphore = asyncio.Semaphore(max_concurrent)

            async def test_with_semaphore(url):
                async with semaphore:
                    return await self.test_api_endpoint(url)

            tasks = [test_with_semaphore(url) for url in all_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter successful results
            api_endpoints = []
            for result in results:
                if isinstance(result, dict) and result.get("is_api", False):
                    api_endpoints.append(result)

            # Sort by confidence and risk level
            api_endpoints.sort(
                key=lambda x: (
                    (
                        1
                        if x.get("risk_level") == "HIGH"
                        else 2 if x.get("risk_level") == "MEDIUM" else 3
                    ),
                    -x.get("confidence", 0),
                )
            )

            self.logger.info(f"🎯 Found {len(api_endpoints)} API endpoints!")

            return api_endpoints

        finally:
            await self.close_session()

    def save_api_results(
        self, api_endpoints: List[Dict], output_dir: str = "api_hunt_results"
    ):
        """Save API hunting results"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Save JSON results
        with open(output_path / "api_endpoints.json", "w") as f:
            json.dump(api_endpoints, f, indent=2, ensure_ascii=False)

        # Save detailed report
        with open(output_path / "api_report.txt", "w", encoding="utf-8") as f:
            f.write("🔥 XSS Vibes V2 - API Endpoint Discovery Report\n")
            f.write("=" * 60 + "\n\n")

            for i, endpoint in enumerate(api_endpoints, 1):
                f.write(f"#### {i}. {endpoint.get('api_type', 'Unknown API')}\n")
                f.write(f"- **Endpoint**: `{endpoint['url']}`\n")
                f.write(f"- **Method**: {endpoint['method']}\n")
                status_text = (
                    "✅ Functional"
                    if endpoint["status_code"] == 200
                    else f"⚠️ Status {endpoint['status_code']}"
                )
                f.write(f"- **Status**: {status_text}\n")
                f.write(f"- **Confidence**: {endpoint['confidence']}%\n")
                f.write(f"- **Risk Level**: {endpoint['risk_level']}\n")

                if endpoint.get("data_extracted"):
                    f.write(f"- **Data Exposed**:\n")
                    f.write(f"  ```json\n")
                    f.write(
                        f"  {json.dumps(endpoint['data_extracted'], indent=2, ensure_ascii=False)}\n"
                    )
                    f.write(f"  ```\n")

                if endpoint.get("indicators"):
                    f.write(
                        f"- **Detection Indicators**: {', '.join(endpoint['indicators'])}\n"
                    )

                f.write("\n")

        # Generate HTML report
        self.generate_api_html_report(api_endpoints, output_path)

        self.logger.info(f"📊 API results saved to {output_path}")

    def generate_api_html_report(self, api_endpoints: List[Dict], output_path: Path):
        """Generate HTML report for API hunting"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vibes V2 - API Endpoint Hunter</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; text-align: center; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .endpoint {{ background: white; margin: 15px 0; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .high-risk {{ border-left: 5px solid #e53e3e; }}
                .medium-risk {{ border-left: 5px solid #dd6b20; }}
                .low-risk {{ border-left: 5px solid #38a169; }}
                .url {{ font-size: 1.2em; font-weight: bold; color: #2d3748; margin-bottom: 10px; word-break: break-all; }}
                .risk {{ display: inline-block; padding: 5px 10px; border-radius: 20px; color: white; font-weight: bold; }}
                .high {{ background: #e53e3e; }}
                .medium {{ background: #dd6b20; }}
                .low {{ background: #38a169; }}
                .data-box {{ background: #f7fafc; padding: 15px; border-radius: 8px; margin: 10px 0; font-family: monospace; }}
                .indicators {{ margin: 10px 0; }}
                .indicator {{ background: #e6fffa; padding: 8px; margin: 5px 0; border-radius: 5px; border-left: 3px solid #38b2ac; }}
                .method {{ background: #4299e1; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 XSS Vibes V2 - API Endpoint Hunter</h1>
                <p>Advanced reconnaissance for API discovery and analysis</p>
                <p>Report generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <h3>{len(api_endpoints)}</h3>
                    <p>API Endpoints Found</p>
                </div>
                <div class="stat">
                    <h3>{len([e for e in api_endpoints if e.get('risk_level') == 'HIGH'])}</h3>
                    <p>High Risk APIs</p>
                </div>
                <div class="stat">
                    <h3>{len([e for e in api_endpoints if e.get('data_extracted')])}</h3>
                    <p>With Exposed Data</p>
                </div>
                <div class="stat">
                    <h3>{len(set([e['url'].split('/')[2] for e in api_endpoints if '/' in e['url']]))}</h3>
                    <p>Unique Domains</p>
                </div>
            </div>
        """

        for i, endpoint in enumerate(api_endpoints, 1):
            risk_level = endpoint.get("risk_level", "LOW").lower()
            risk_class = f"{risk_level}-risk"

            html_content += f"""
            <div class="endpoint {risk_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <span style="font-size: 1.1em; font-weight: bold;">#{i}. {endpoint.get('api_type', 'Unknown API')}</span>
                    <span class="method">{endpoint.get('method', 'GET')}</span>
                </div>
                
                <div class="url">{endpoint['url']}</div>
                
                <div style="margin: 10px 0;">
                    <span class="risk {risk_level}">{endpoint.get('risk_level', 'LOW')} RISK</span>
                    <span style="margin-left: 10px; color: #666;">
                        Status: {endpoint.get('status_code', 'N/A')} | 
                        Confidence: {endpoint.get('confidence', 0)}%
                    </span>
                </div>
                
                {f'''
                <div class="data-box">
                    <h4>🔓 Exposed Data</h4>
                    <pre>{json.dumps(endpoint.get('data_extracted', {}), indent=2, ensure_ascii=False)}</pre>
                </div>
                ''' if endpoint.get('data_extracted') else ''}
                
                <div class="indicators">
                    <h4>📋 Detection Indicators ({len(endpoint.get('indicators', []))})</h4>
                    {chr(10).join([f'<div class="indicator">{indicator}</div>' for indicator in endpoint.get('indicators', [])])}
                </div>
                
                {f'''
                <div style="margin-top: 15px; padding: 10px; background: #fff5f5; border-radius: 5px; border-left: 3px solid #f56565;">
                    <h4 style="color: #c53030; margin: 0;">⚠️ Security Concerns</h4>
                    <p style="margin: 5px 0;">This API endpoint may expose sensitive information including tokens, configuration data, or user information.</p>
                </div>
                ''' if endpoint.get('risk_level') == 'HIGH' else ''}
            </div>
            """

        html_content += """
        </body>
        </html>
        """

        with open(output_path / "api_endpoints.html", "w", encoding="utf-8") as f:
            f.write(html_content)


async def main():
    """Main function for testing"""
    hunter = APIEndpointHunter()

    # Example with Ctrip
    domains = ["ctrip.com"]
    results = await hunter.hunt_api_endpoints(domains)
    hunter.save_api_results(results)

    print(f"🎯 Found {len(results)} API endpoints")
    for result in results[:5]:  # Show top 5
        print(
            f"  {result['url']} - {result['confidence']}% confidence - {result['risk_level']} risk"
        )


if __name__ == "__main__":
    asyncio.run(main())
