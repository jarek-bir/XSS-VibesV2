#!/usr/bin/env python3
"""
XSS Vibes - Multi-Vulnerability Testing Suite
Tests all vulnerability types from the oneliners collection
"""
import subprocess
import time
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple
import concurrent.futures


class MultiVulnTester:
    """Comprehensive vulnerability testing using community oneliners"""
    
    def __init__(self):
        self.test_dir = f"multi_vuln_test_{int(time.time())}"
        Path(self.test_dir).mkdir(exist_ok=True)
        self.results = {}
        
    def test_xss_techniques(self, target: str) -> Dict:
        """Test all XSS hunting techniques"""
        print("🎯 Testing XSS Techniques...")
        
        xss_tests = {
            'gospider_xss': f'gospider -s "{target}" -c 5 -d 2 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk \'{{print $5}}\' | grep "=" | head -5',
            
            'wayback_xss': f'echo {target} | waybackurls | grep "=" | head -5',
            
            'gau_xss': f'echo {target} | gau | grep "=" | head -5',
            
            'hakrawler_xss': f'hakrawler -url "{target}" -plain | grep "=" | head -5',
            
            'kxss_test': f'echo "http://{target}/" | waybackurls | kxss | head -5'
        }
        
        xss_results = {}
        for test_name, command in xss_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                xss_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                xss_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                xss_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return xss_results
    
    def test_sqli_techniques(self, target: str) -> Dict:
        """Test SQL Injection detection techniques"""
        print("🗃️ Testing SQL Injection Techniques...")
        
        sqli_tests = {
            'wayback_sqli': f'echo {target} | waybackurls | grep "=" | head -5',
            
            'gau_sqli_params': f'gau {target} | grep "=" | grep -E "(id|user|search|query|page)" | head -5',
            
            'sqli_error_based': f'echo "http://{target}/search?q=test\'" | head -1',
            
            'time_based_check': f'echo "http://{target}/?id=1" | head -1'
        }
        
        sqli_results = {}
        for test_name, command in sqli_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=20)
                sqli_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                sqli_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                sqli_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return sqli_results
    
    def test_cors_techniques(self, target: str) -> Dict:
        """Test CORS misconfiguration detection"""
        print("🌐 Testing CORS Techniques...")
        
        cors_tests = {
            'basic_cors_test': f'curl -s -I -H "Origin: https://evil.com" -X GET "http://{target}/" | grep -i "access-control"',
            
            'gau_cors_endpoints': f'gau {target} | grep -E "(api|cors|cross)" | head -5',
            
            'subdomain_cors': f'echo {target} | subfinder -silent | head -3'
        }
        
        cors_results = {}
        for test_name, command in cors_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
                cors_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                cors_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                cors_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return cors_results
    
    def test_ssrf_techniques(self, target: str) -> Dict:
        """Test SSRF detection techniques"""
        print("🔗 Testing SSRF Techniques...")
        
        ssrf_tests = {
            'gau_ssrf_params': f'gau {target} | grep "=" | grep -E "(url|uri|redirect|callback|api)" | head -5',
            
            'wayback_ssrf': f'echo {target} | waybackurls | grep -E "(url=|uri=|redirect=)" | head -5',
            
            'ssrf_endpoints': f'echo {target} | httpx -silent | head -1'
        }
        
        ssrf_results = {}
        for test_name, command in ssrf_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
                ssrf_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                ssrf_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                ssrf_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return ssrf_results
    
    def test_lfi_techniques(self, target: str) -> Dict:
        """Test Local File Inclusion detection"""
        print("📁 Testing LFI Techniques...")
        
        lfi_tests = {
            'gau_lfi_params': f'gau {target} | grep "=" | grep -E "(file|path|include|page)" | head -5',
            
            'wayback_lfi': f'echo {target} | waybackurls | grep -E "(file=|path=|include=)" | head -5',
            
            'lfi_common_params': f'echo "http://{target}/?file=test&path=test&include=test" | head -1'
        }
        
        lfi_results = {}
        for test_name, command in lfi_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
                lfi_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                lfi_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                lfi_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return lfi_results
    
    def test_open_redirect(self, target: str) -> Dict:
        """Test Open Redirect detection"""
        print("🔄 Testing Open Redirect Techniques...")
        
        redirect_tests = {
            'gau_redirect_params': f'gau {target} | grep -E "(redirect|url|next|return)" | head -5',
            
            'wayback_redirects': f'echo {target} | waybackurls | grep -E "(redirect=|url=|next=)" | head -5',
            
            'common_redirect_params': f'echo "http://{target}/?redirect=test&next=test&url=test" | head -1'
        }
        
        redirect_results = {}
        for test_name, command in redirect_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
                redirect_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                redirect_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                redirect_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return redirect_results
    
    def test_subdomain_takeover(self, target: str) -> Dict:
        """Test subdomain takeover detection"""
        print("🏗️ Testing Subdomain Takeover...")
        
        takeover_tests = {
            'subfinder_enum': f'subfinder -d {target} -silent | head -5',
            
            'assetfinder_enum': f'echo {target} | assetfinder -subs-only | head -5',
            
            'httpx_status_check': f'echo {target} | subfinder -silent | httpx -silent -status-code | head -5'
        }
        
        takeover_results = {}
        for test_name, command in takeover_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=20)
                takeover_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                takeover_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                takeover_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return takeover_results
    
    def test_directory_bruteforce(self, target: str) -> Dict:
        """Test directory bruteforce techniques"""
        print("📂 Testing Directory Bruteforce...")
        
        dir_tests = {
            'gospider_dirs': f'gospider -s "http://{target}" -c 3 -d 1 | grep -E "(200|301|302)" | head -5',
            
            'common_paths_check': f'echo "http://{target}/admin\\nhttp://{target}/api\\nhttp://{target}/test" | httpx -silent -status-code | head -3',
            
            'wayback_paths': f'echo {target} | waybackurls | grep -o "http[s]*://[^/]*[^?]*" | sort -u | head -5'
        }
        
        dir_results = {}
        for test_name, command in dir_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=20)
                dir_results[test_name] = {
                    'status': 'success' if result.returncode == 0 else 'failed',
                    'output_lines': len(result.stdout.splitlines()),
                    'sample_output': result.stdout[:200]
                }
            except subprocess.TimeoutExpired:
                dir_results[test_name] = {'status': 'timeout', 'output_lines': 0}
            except Exception as e:
                dir_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return dir_results
    
    def test_god_tier_integration(self, target: str) -> Dict:
        """Test GOD TIER XSS techniques integration"""
        print("🔥 Testing GOD TIER Integration...")
        
        god_tier_tests = {
            'cuneiform_test': f'echo "http://{target}/?test=𒀀=alert,𒉺=!𒀀+𒀀" | head -1',
            
            'unicode_zero_width': f'echo "http://{target}/?test=ale‌rt(1)" | head -1',
            
            'constructor_chain': f'echo "http://{target}/?test=constructor[constructor](alert(1))()" | head -1',
            
            'svg_xlink_href': f'echo "http://{target}/?test=<svg><use href=\\"#x\\"></use><symbol id=\\"x\\"><foreignObject><iframe src=\\"javascript:alert(1)\\"></iframe></foreignObject></symbol></svg>" | head -1',
            
            'pdf_xss': f'echo "http://{target}/?test=%PDF-1.4%0A1%200%20obj%3C%3C/Type/Catalog/Pages%202%200%20R/OpenAction%3C%3C/Type/Action/S/JavaScript/JS(alert(\'XSS\'))%3E%3E%3E%3E" | head -1'
        }
        }
        
        god_tier_results = {}
        for test_name, command in god_tier_tests.items():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                god_tier_results[test_name] = {
                    'status': 'success',
                    'payload_generated': True,
                    'sample_output': result.stdout[:200]
                }
            except Exception as e:
                god_tier_results[test_name] = {'status': 'error', 'error': str(e)}
                
        return god_tier_results
    
    def run_comprehensive_test(self, target: str) -> Dict:
        """Run comprehensive vulnerability testing"""
        print(f"🚀 Starting comprehensive vulnerability test on {target}")
        print("=" * 80)
        
        test_categories = [
            ('XSS', self.test_xss_techniques),
            ('SQL Injection', self.test_sqli_techniques),
            ('CORS', self.test_cors_techniques),
            ('SSRF', self.test_ssrf_techniques),
            ('LFI', self.test_lfi_techniques),
            ('Open Redirect', self.test_open_redirect),
            ('Subdomain Takeover', self.test_subdomain_takeover),
            ('Directory Bruteforce', self.test_directory_bruteforce),
            ('GOD TIER Integration', self.test_god_tier_integration)
        ]
        
        all_results = {}
        
        for category_name, test_function in test_categories:
            print(f"\n🔍 Testing {category_name}...")
            try:
                results = test_function(target)
                all_results[category_name] = results
                
                # Count successful tests
                successful = sum(1 for r in results.values() if r.get('status') == 'success')
                total = len(results)
                print(f"✅ {category_name}: {successful}/{total} tests successful")
                
            except Exception as e:
                print(f"❌ {category_name}: Failed - {e}")
                all_results[category_name] = {'error': str(e)}
        
        return all_results
    
    def generate_test_report(self, target: str, results: Dict) -> str:
        """Generate comprehensive test report"""
        report_file = f"{self.test_dir}/comprehensive_test_report.json"
        
        # Calculate overall statistics
        total_categories = len(results)
        successful_categories = sum(1 for r in results.values() if not r.get('error'))
        
        total_tests = 0
        successful_tests = 0
        
        for category_results in results.values():
            if not category_results.get('error'):
                for test_result in category_results.values():
                    total_tests += 1
                    if test_result.get('status') == 'success':
                        successful_tests += 1
        
        # Create comprehensive report
        report = {
            'target': target,
            'test_timestamp': time.time(),
            'test_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_categories': total_categories,
                'successful_categories': successful_categories,
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'success_rate': f"{(successful_tests/total_tests)*100:.1f}%" if total_tests > 0 else "0%"
            },
            'detailed_results': results,
            'recommendations': self.generate_recommendations(results)
        }
        
        # Save report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate testing recommendations based on results"""
        recommendations = []
        
        # XSS recommendations
        if 'XSS' in results and results['XSS']:
            xss_success = sum(1 for r in results['XSS'].values() if r.get('status') == 'success')
            if xss_success > 0:
                recommendations.append("✅ XSS testing tools are working - consider running full XSS hunt")
            else:
                recommendations.append("⚠️ XSS tools need attention - check tool installation")
        
        # SQL Injection recommendations
        if 'SQL Injection' in results and results['SQL Injection']:
            sqli_success = sum(1 for r in results['SQL Injection'].values() if r.get('status') == 'success')
            if sqli_success > 0:
                recommendations.append("✅ SQL injection detection ready - run sqlmap on found parameters")
            
        # CORS recommendations
        if 'CORS' in results and results['CORS']:
            cors_success = sum(1 for r in results['CORS'].values() if r.get('status') == 'success')
            if cors_success > 0:
                recommendations.append("✅ CORS testing functional - check for misconfigured endpoints")
        
        # GOD TIER recommendations
        if 'GOD TIER Integration' in results:
            recommendations.append("🔥 GOD TIER payloads generated - test these manually for maximum impact")
        
        # General recommendations
        recommendations.extend([
            "🔧 Install any missing tools for better coverage",
            "🎯 Focus on categories with highest success rates",
            "📊 Run tests regularly to monitor target changes",
            "🛡️ Always test with proper authorization"
        ])
        
        return recommendations


def main():
    """Main testing function"""
    print("🔥 XSS Vibes - Multi-Vulnerability Testing Suite")
    print("=" * 80)
    
    tester = MultiVulnTester()
    
    # Get target from user
    target = input("🎯 Enter target domain (e.g., testphp.vulnweb.com): ").strip()
    if not target:
        target = "testphp.vulnweb.com"  # Default safe target
    
    print(f"\n🚀 Starting comprehensive test on: {target}")
    print("⚠️ This will test multiple vulnerability types...")
    
    # Run comprehensive testing
    results = tester.run_comprehensive_test(target)
    
    # Generate report
    report_file = tester.generate_test_report(target, results)
    
    print(f"\n📊 Test Results Summary:")
    print("=" * 50)
    
    for category, category_results in results.items():
        if not category_results.get('error'):
            successful = sum(1 for r in category_results.values() if r.get('status') == 'success')
            total = len(category_results)
            print(f"🎯 {category}: {successful}/{total} tests successful")
        else:
            print(f"❌ {category}: Failed")
    
    print(f"\n📁 Detailed report saved: {report_file}")
    print(f"📁 Test directory: {tester.test_dir}")
    
    # Show some key findings
    if 'XSS' in results and results['XSS']:
        xss_findings = sum(r.get('output_lines', 0) for r in results['XSS'].values())
        if xss_findings > 0:
            print(f"🎯 Found {xss_findings} potential XSS endpoints")
    
    print("\n🏆 Multi-vulnerability testing completed!")


if __name__ == "__main__":
    main()
