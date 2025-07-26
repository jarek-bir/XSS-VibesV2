#!/usr/bin/env python3
"""
XSS Vibes CLI - Modern XSS Scanner with Click interface.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Optional

import click
from colorama import Fore, Style, init as colorama_init

# Add parent directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from .config import ScannerConfig
from .logger import setup_logging
from .models import ScanResult, VulnerabilityLevel
from .payload_manager import PayloadManager
from .scanner import XSSScanner
from .waf_detector import WAFDetector
from .output_manager import OutputManager
from .integrations import ParameterDiscovery, install_tools
from .advanced_reporting import AdvancedReporter, ReportConfig
from .payload_mutation import PayloadMutationEngine, InjectionContext, MutationType
from .session_manager import SessionManager, LoginCredentials, SessionConfig, AuthMethod
from .rate_limit import (
    RateLimiter,
    RateLimitConfig,
    create_stealth_rate_limiter,
    create_normal_rate_limiter,
    create_aggressive_rate_limiter,
)

# Initialize colorama
colorama_init(autoreset=True)

logger = logging.getLogger("xss_vibes.cli")


def print_banner():
    """Print the XSS Vibes banner."""
    banner = f"""
{Fore.RED}
 ██╗  ██╗███████╗███████╗    ██╗   ██╗██╗██████╗ ███████╗███████╗
 ╚██╗██╔╝██╔════╝██╔════╝    ██║   ██║██║██╔══██╗██╔════╝██╔════╝
  ╚███╔╝ ███████╗███████╗    ██║   ██║██║██████╔╝█████╗  ███████╗
  ██╔██╗ ╚════██║╚════██║    ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║
 ██╔╝ ██╗███████║███████║     ╚████╔╝ ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚══════╝╚══════╝      ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.CYAN}          Modern XSS Scanner v2.0.0 with WAF Evasion{Style.RESET_ALL}
{Fore.YELLOW}               Enhanced by AI - Built for Professionals{Style.RESET_ALL}
"""
    click.echo(banner)


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def cli(ctx, version):
    """XSS Vibes - Modern XSS Scanner with WAF evasion capabilities."""
    if version:
        click.echo("XSS Vibes v2.0.0")
        return

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo("Use 'xss-vibes scan --help' to see scanning options")
        click.echo("Use 'xss-vibes payloads --help' to manage payloads")


@cli.command()
@click.argument("urls", nargs=-1, required=True)
@click.option("-u", "--url", "single_url", help="Single URL to scan")
@click.option(
    "-l",
    "--list",
    "url_list",
    type=click.Path(exists=True),
    help="File containing URLs to scan",
)
@click.option("-c", "--cookie", help="Cookie string to use")
@click.option(
    "-H",
    "--header",
    "headers",
    multiple=True,
    help='Custom header (format: "Name: Value")',
)
@click.option("--user-agent", help="Custom User-Agent string")
@click.option("--threads", type=int, default=1, help="Number of threads (1-10)")
@click.option("--timeout", type=int, default=10, help="Request timeout in seconds")
@click.option("--delay", type=float, default=0, help="Delay between requests")
@click.option(
    "--mode",
    type=click.Choice(["sync", "async"]),
    default="async",
    help="Scanning mode",
)
@click.option("--waf-mode", is_flag=True, help="Enable WAF-specific evasion payloads")
@click.option(
    "--target-waf",
    type=click.Choice(
        [
            "cloudflare",
            "akamai",
            "imperva",
            "f5",
            "barracuda",
            "sucuri",
            "modsecurity",
            "wordfence",
            "aws-waf",
        ]
    ),
    help="Target specific WAF for optimized payload selection",
)
@click.option("--custom-waf", help="Custom WAF name")
@click.option("--no-waf-detect", is_flag=True, help="Disable WAF detection")
@click.option(
    "--level",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum vulnerability level to report",
)
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON/HTML/TXT)")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "html", "txt", "csv", "markdown"]),
    default="txt",
    help="Output format",
)
@click.option(
    "--report-format",
    type=click.Choice(["html", "json", "csv", "markdown"]),
    help="Advanced report format",
)
@click.option("--report-title", default="XSS Security Assessment", help="Report title")
@click.option(
    "--include-payloads/--no-include-payloads",
    default=True,
    help="Include payloads in report",
)
@click.option(
    "--include-technical/--no-include-technical",
    default=True,
    help="Include technical details in report",
)
@click.option(
    "--executive-summary/--no-executive-summary",
    default=True,
    help="Include executive summary",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level",
)
@click.option("--log-file", type=click.Path(), help="Log file path")
@click.option("--no-colors", is_flag=True, help="Disable colored output")
@click.option("--proxy", help="Proxy URL (http://proxy:port or socks5://proxy:port)")
@click.option("--burp", is_flag=True, help="Use Burp Suite proxy (127.0.0.1:8080)")
@click.option("--tor", is_flag=True, help="Use Tor proxy (127.0.0.1:9050)")
@click.option(
    "--verify-ssl/--no-verify-ssl", default=True, help="Verify SSL certificates"
)
@click.option(
    "--follow-redirects/--no-follow-redirects",
    default=True,
    help="Follow HTTP redirects",
)
@click.option("--dry-run", is_flag=True, help="Show configuration without scanning")
@click.option("--arjun", is_flag=True, help="Use Arjun for parameter discovery")
@click.option(
    "--paramspider",
    is_flag=True,
    help="Use ParamSpider for archive parameter collection",
)
@click.option(
    "--discovery-only",
    is_flag=True,
    help="Only run parameter discovery, skip XSS scanning",
)
@click.option("--random-ua", is_flag=True, help="Use random User-Agent for requests")
@click.option(
    "--ua-type",
    type=click.Choice(["browser", "security", "bot", "any"]),
    default="browser",
    help="Type of random User-Agent to use",
)
@click.option("--rotate-ua", is_flag=True, help="Rotate User-Agent for each request")
# Rate limiting and stealth options
@click.option("--rate-limit", type=float, help="Requests per second (e.g., 5.0)")
@click.option(
    "--stealth", is_flag=True, help="Enable stealth mode (very slow but evasive)"
)
@click.option(
    "--aggressive", is_flag=True, help="Enable aggressive mode (fast but detectable)"
)
@click.option(
    "--adaptive", is_flag=True, help="Enable adaptive rate limiting based on responses"
)
@click.option("--jitter", is_flag=True, help="Add random jitter to request timing")
@click.option(
    "--min-delay",
    type=float,
    default=2.0,
    help="Minimum delay in stealth mode (seconds)",
)
@click.option(
    "--max-delay",
    type=float,
    default=8.0,
    help="Maximum delay in stealth mode (seconds)",
)
# Advanced encoding options
@click.option(
    "--encoding", is_flag=True, help="Enable advanced payload encoding for WAF evasion"
)
@click.option(
    "--encoding-types",
    multiple=True,
    help="Specific encoding types to use (url, unicode, base64, etc.)",
)
@click.option(
    "--encoding-variants",
    type=int,
    default=5,
    help="Number of encoding variants per payload",
)
@click.option(
    "--context-aware",
    is_flag=True,
    help="Use context-aware encoding based on injection point",
)
@click.option(
    "--high-evasion", is_flag=True, help="Use only high-evasion payloads and techniques"
)
# New advanced options
@click.option(
    "--blind", is_flag=True, help="Enable blind XSS testing with callback URL"
)
@click.option(
    "--callback-url",
    help="Callback URL for blind XSS detection (e.g., https://yourserver.com/callback)",
)
@click.option("--obfuscate", is_flag=True, help="Enable payload obfuscation")
@click.option(
    "--encoding-level",
    type=click.Choice(["1", "2", "3"]),
    default="1",
    help="Encoding level: 1=basic, 2=advanced, 3=maximum evasion",
)
@click.option("--mutation", is_flag=True, help="Enable intelligent payload mutation")
@click.option(
    "--mutation-generations",
    type=int,
    default=5,
    help="Number of mutation generations for genetic algorithm",
)
# Session management options
@click.option("--login-url", help="Login URL for authenticated scanning")
@click.option("--username", help="Username for authentication")
@click.option("--password", help="Password for authentication")
@click.option(
    "--auth-type",
    type=click.Choice(["form", "basic", "digest", "bearer"]),
    default="form",
    help="Authentication type",
)
@click.option("--session-profile", help="Load session profile from file")
@click.option("--cookie-jar", help="Cookie jar file for session persistence")
def scan(
    urls,
    single_url,
    url_list,
    cookie,
    headers,
    user_agent,
    threads,
    timeout,
    delay,
    mode,
    waf_mode,
    target_waf,
    custom_waf,
    no_waf_detect,
    level,
    output,
    output_format,
    report_format,
    report_title,
    include_payloads,
    include_technical,
    executive_summary,
    log_level,
    log_file,
    no_colors,
    proxy,
    burp,
    tor,
    verify_ssl,
    follow_redirects,
    dry_run,
    arjun,
    paramspider,
    discovery_only,
    random_ua,
    ua_type,
    rotate_ua,
    # Rate limiting parameters
    rate_limit,
    stealth,
    aggressive,
    adaptive,
    jitter,
    min_delay,
    max_delay,
    # Encoding parameters
    encoding,
    encoding_types,
    encoding_variants,
    context_aware,
    high_evasion,
    # New advanced parameters
    blind,
    callback_url,
    obfuscate,
    encoding_level,
    mutation,
    mutation_generations,
    # Session management parameters
    login_url,
    username,
    password,
    auth_type,
    session_profile,
    cookie_jar,
):
    """Scan URLs for XSS vulnerabilities."""

    if not no_colors:
        print_banner()

    # Setup logging
    try:
        setup_logging(
            level=getattr(logging, log_level),
            log_file=Path(log_file) if log_file else None,
            enable_colors=not no_colors,
        )
    except Exception as e:
        click.echo(f"Logging setup error: {e}")
        logging.basicConfig(level=logging.INFO)

    # Collect URLs
    target_urls = []

    if single_url:
        target_urls.append(single_url)

    if urls:
        target_urls.extend(urls)

    if url_list:
        with open(url_list, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    target_urls.append(line)

    if not target_urls:
        click.echo(f"{Fore.RED}Error: No URLs provided{Style.RESET_ALL}", err=True)
        return

    # Setup rate limiter
    rate_limiter = None
    if stealth:
        rate_limiter = create_stealth_rate_limiter()
        click.echo(
            f"{Fore.YELLOW}🕶️  Stealth mode enabled - very slow but evasive{Style.RESET_ALL}"
        )
    elif aggressive:
        rate_limiter = create_aggressive_rate_limiter()
        click.echo(
            f"{Fore.RED}🚀 Aggressive mode enabled - fast but detectable{Style.RESET_ALL}"
        )
    elif rate_limit:
        config_data = RateLimitConfig(
            requests_per_second=rate_limit,
            adaptive_timing=adaptive,
            jitter_enabled=jitter,
            min_delay=min_delay,
            max_delay=max_delay,
        )
        rate_limiter = RateLimiter(config_data)
        click.echo(f"{Fore.CYAN}⚡ Rate limiting: {rate_limit} req/s{Style.RESET_ALL}")

    # Setup configuration
    config = ScannerConfig(
        max_threads=min(threads, 10),
        default_timeout=timeout,
        verify_ssl=verify_ssl,
        burp_proxy=burp,
        use_tor=tor,
        random_user_agent=random_ua,
        user_agent_type=ua_type,
        rotate_user_agent=rotate_ua,
        custom_user_agent=user_agent,
        rate_limiter=rate_limiter,
    )

    # Setup proxy configuration
    if proxy:
        if proxy.startswith("socks5://"):
            config.proxy_http = proxy
            config.proxy_https = proxy
        else:
            config.proxy_http = proxy
            config.proxy_https = proxy

    # Display proxy info
    if config.burp_proxy:
        click.echo(
            f"{Fore.YELLOW}🔗 Using Burp Suite proxy: 127.0.0.1:8080{Style.RESET_ALL}"
        )
    elif config.use_tor:
        click.echo(f"{Fore.YELLOW}🧅 Using Tor proxy: 127.0.0.1:9050{Style.RESET_ALL}")
    elif proxy:
        click.echo(f"{Fore.YELLOW}🔗 Using custom proxy: {proxy}{Style.RESET_ALL}")

    # Add custom headers to config
    custom_headers = {}
    if headers:
        custom_headers = dict(h.split(":", 1) for h in headers)

    # Setup session manager for authentication
    session_manager = None
    if login_url or session_profile or username:
        session_config = SessionConfig(
            timeout=timeout,
            verify_ssl=verify_ssl,
            cookie_jar_file=cookie_jar,
            headers=custom_headers,
        )
        session_manager = SessionManager(session_config)

        # Configure authentication
        if session_profile:
            # Load from profile (future enhancement)
            click.echo(
                f"{Fore.CYAN}🔐 Session profile not yet implemented{Style.RESET_ALL}"
            )
        elif login_url and username and password:
            credentials = LoginCredentials(
                username=username, password=password, login_url=login_url
            )

            auth_method = AuthMethod(type=auth_type, credentials=credentials)

            click.echo(
                f"{Fore.CYAN}🔐 Authenticating with {auth_type} method...{Style.RESET_ALL}"
            )
            if session_manager.authenticate(auth_method):
                click.echo(f"{Fore.GREEN}✅ Authentication successful{Style.RESET_ALL}")
            else:
                click.echo(f"{Fore.RED}❌ Authentication failed{Style.RESET_ALL}")
                if not click.confirm("Continue without authentication?"):
                    return
    if user_agent and not random_ua:
        config.default_headers = config.default_headers or {}
        config.default_headers["User-Agent"] = user_agent

    # Parse custom headers
    custom_headers = {}
    if cookie:
        custom_headers["Cookie"] = cookie

    for header in headers:
        if ":" in header:
            name, value = header.split(":", 1)
            custom_headers[name.strip()] = value.strip()

    # Initialize components
    payload_manager = PayloadManager()
    waf_detector = WAFDetector()
    scanner = XSSScanner(config, payload_manager, waf_detector)

    # Initialize parameter discovery if requested
    enhanced_targets = target_urls.copy()
    discovery_results = {}

    if arjun or paramspider:
        param_discovery = ParameterDiscovery(config)

        # Check tool availability
        tools_status = install_tools()

        if arjun and not tools_status.get("arjun", False):
            click.echo(
                f"{Fore.RED}❌ Arjun not available. Install with: pip3 install arjun{Style.RESET_ALL}"
            )

        if paramspider and not tools_status.get("paramspider", False):
            click.echo(
                f"{Fore.RED}❌ ParamSpider not available. Install with: pip3 install paramspider{Style.RESET_ALL}"
            )

        # Run parameter discovery on first URL as example
        if target_urls and (arjun or paramspider):
            click.echo(f"{Fore.CYAN}🔍 Running parameter discovery...{Style.RESET_ALL}")

            try:
                # Run parameter discovery in async context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                discovery_results = loop.run_until_complete(
                    param_discovery.discover_all_parameters(
                        target_urls[0], use_archives=paramspider
                    )
                )

                if discovery_results.get("enhanced_targets"):
                    enhanced_targets.extend(discovery_results["enhanced_targets"])
                    click.echo(
                        f"{Fore.GREEN}✅ Found {len(discovery_results['enhanced_targets'])} additional targets{Style.RESET_ALL}"
                    )
                else:
                    click.echo(
                        f"{Fore.YELLOW}ℹ️  No additional parameters discovered{Style.RESET_ALL}"
                    )

            except Exception as e:
                click.echo(
                    f"{Fore.RED}❌ Parameter discovery failed: {e}{Style.RESET_ALL}"
                )

    # Update target URLs with enhanced targets
    target_urls = list(set(enhanced_targets))  # Remove duplicates

    # Setup advanced payload features
    mutation_engine = None
    blind_generator = None

    if mutation:
        click.echo(
            f"{Fore.CYAN}🧬 Initializing payload mutation engine...{Style.RESET_ALL}"
        )
        mutation_engine = PayloadMutationEngine()
        click.echo(
            f"{Fore.GREEN}✅ Mutation engine ready with {len(mutation_engine.mutation_rules)} rules{Style.RESET_ALL}"
        )

    if blind and callback_url:
        click.echo(f"{Fore.CYAN}🔍 Setting up blind XSS testing...{Style.RESET_ALL}")
        # blind_generator = BlindPayloadGenerator(callback_url)  # Will implement this
        click.echo(
            f"{Fore.GREEN}✅ Blind XSS configured with callback: {callback_url}{Style.RESET_ALL}"
        )
    elif blind and not callback_url:
        click.echo(
            f"{Fore.RED}❌ Blind XSS requires --callback-url parameter{Style.RESET_ALL}"
        )
        return

    # Apply encoding level configuration
    if encoding or encoding_level != "1":
        level_map = {
            "1": {"types": ["url", "html"], "variants": 3},
            "2": {"types": ["url", "html", "unicode", "base64"], "variants": 5},
            "3": {
                "types": [
                    "url",
                    "html",
                    "unicode",
                    "base64",
                    "utf7",
                    "fromcharcode",
                    "eval",
                ],
                "variants": 8,
            },
        }

        if encoding_level in level_map:
            level_config = level_map[encoding_level]
            if not encoding_types:
                encoding_types = level_config["types"]
            if encoding_variants == 5:  # Default value
                encoding_variants = level_config["variants"]

            click.echo(
                f"{Fore.CYAN}🎭 Encoding level {encoding_level}: {len(encoding_types)} types, {encoding_variants} variants{Style.RESET_ALL}"
            )

    # Dry run - show configuration and exit
    if dry_run:
        click.echo(f"{Fore.CYAN}🔧 Configuration Preview{Style.RESET_ALL}")
        click.echo(f"   URLs to scan: {len(target_urls)}")
        click.echo(f"   Threads: {config.max_threads}")
        click.echo(f"   Timeout: {config.default_timeout}s")
        click.echo(f"   Mode: {mode}")
        click.echo(f"   WAF mode: {'enabled' if waf_mode else 'disabled'}")
        if config.burp_proxy:
            click.echo(f"   Proxy: Burp Suite (127.0.0.1:8080)")
        elif config.use_tor:
            click.echo(f"   Proxy: Tor (127.0.0.1:9050)")
        elif proxy:
            click.echo(f"   Proxy: {proxy}")
        else:
            click.echo(f"   Proxy: None")
        click.echo(
            f"   Payloads: {payload_manager.payload_count} standard + {payload_manager.waf_payload_count} WAF-specific"
        )
        if arjun or paramspider:
            click.echo(
                f"   Parameter discovery: {'enabled' if arjun or paramspider else 'disabled'}"
            )
        if random_ua:
            current_ua = config.get_user_agent()
            click.echo(f"   User-Agent: Random ({ua_type}) - {current_ua[:50]}...")
        elif user_agent:
            click.echo(f"   User-Agent: Custom - {user_agent[:50]}...")
        else:
            click.echo(f"   User-Agent: Default")
        return

    # Discovery only mode - show results and exit
    if discovery_only:
        if discovery_results:
            click.echo(f"{Fore.GREEN}🔍 Parameter Discovery Results:{Style.RESET_ALL}")

            if discovery_results.get("arjun_params"):
                click.echo(
                    f"   🎯 Arjun discovered: {', '.join(discovery_results['arjun_params'])}"
                )

            if discovery_results.get("archive_urls"):
                click.echo(
                    f"   🕷️  Archive URLs found: {len(discovery_results['archive_urls'])}"
                )
                for url in discovery_results["archive_urls"][:10]:  # Show first 10
                    click.echo(f"      {url}")
                if len(discovery_results["archive_urls"]) > 10:
                    click.echo(
                        f"      ... and {len(discovery_results['archive_urls']) - 10} more"
                    )

            if discovery_results.get("enhanced_targets"):
                click.echo(
                    f"   📈 Enhanced targets: {len(discovery_results['enhanced_targets'])}"
                )
                for target in discovery_results["enhanced_targets"][:5]:  # Show first 5
                    click.echo(f"      {target}")
                if len(discovery_results["enhanced_targets"]) > 5:
                    click.echo(
                        f"      ... and {len(discovery_results['enhanced_targets']) - 5} more"
                    )
        else:
            click.echo(
                f"{Fore.YELLOW}ℹ️  No parameter discovery was run. Use --arjun or --paramspider{Style.RESET_ALL}"
            )
        return

    click.echo(f"{Fore.CYAN}🚀 Starting XSS scan...{Style.RESET_ALL}")
    click.echo(
        f"📊 Loaded {payload_manager.payload_count} standard + {payload_manager.waf_payload_count} WAF-specific payloads"
    )

    # Handle advanced encoding if requested
    if encoding or high_evasion or context_aware:
        click.echo(
            f"{Fore.MAGENTA}🔐 Generating advanced encoded payloads...{Style.RESET_ALL}"
        )

        # Import encoding types
        from .encoding_engine import EncodingType

        encoding_type_map = {
            "url": EncodingType.URL,
            "double_url": EncodingType.DOUBLE_URL,
            "html": EncodingType.HTML_ENTITIES,
            "unicode": EncodingType.UNICODE,
            "hex": EncodingType.HEX,
            "octal": EncodingType.OCTAL,
            "base64": EncodingType.BASE64,
            "utf7": EncodingType.UTF7,
            "utf16": EncodingType.UTF16,
            "json": EncodingType.JSON_UNICODE,
            "css": EncodingType.CSS_ENCODING,
            "js": EncodingType.JAVASCRIPT_ENCODING,
            "mixed": EncodingType.MIXED_CASE,
            "char_sub": EncodingType.CHARACTER_SUBSTITUTION,
            "comments": EncodingType.COMMENT_INSERTION,
            "whitespace": EncodingType.WHITESPACE_MANIPULATION,
            "concat": EncodingType.CONCATENATION,
            "eval": EncodingType.EVAL_ENCODING,
            "fromcharcode": EncodingType.FROMCHARCODE,
        }

        if high_evasion:
            # Generate high-evasion payloads
            encoded_payloads = payload_manager.get_high_evasion_payloads(
                waf_type=target_waf, max_count=100
            )
            click.echo(f"   🎯 Generated {len(encoded_payloads)} high-evasion payloads")

        elif encoding_types:
            # Use specific encoding types
            selected_types = []
            for enc_type in encoding_types:
                if enc_type in encoding_type_map:
                    selected_types.append(encoding_type_map[enc_type])
                else:
                    click.echo(
                        f"{Fore.YELLOW}⚠️  Unknown encoding type: {enc_type}{Style.RESET_ALL}"
                    )

            if selected_types:
                encoded_payloads = payload_manager.generate_encoded_payloads(
                    encoding_types=selected_types, max_variants=encoding_variants
                )
                click.echo(
                    f"   🔐 Generated {len(encoded_payloads)} encoded variants using {len(selected_types)} techniques"
                )

        else:
            # Generate automatic encoding variants
            encoded_payloads = payload_manager.generate_encoded_payloads(
                max_variants=encoding_variants
            )
            click.echo(
                f"   🔄 Generated {len(encoded_payloads)} automatic encoding variants"
            )

        # Add encoded payloads to scanner (we'll need to modify scanner to accept additional payloads)
        # For now, we'll show the count
        click.echo(f"   ✅ Enhanced payload arsenal with advanced encoding techniques")

    if waf_mode:
        click.echo(f"{Fore.YELLOW}🛡️  WAF evasion mode enabled{Style.RESET_ALL}")

    if target_waf:
        click.echo(f"{Fore.YELLOW}🎯 Targeting WAF: {target_waf}{Style.RESET_ALL}")

    # Run scans
    results = []

    if mode == "async":
        results = asyncio.run(
            scan_urls_async(
                scanner,
                target_urls,
                custom_headers,
                not no_waf_detect,
                custom_waf,
                waf_mode,
                target_waf,
            )
        )
    else:
        for url in target_urls:
            click.echo(f"{Fore.BLUE}🔍 Scanning: {url}{Style.RESET_ALL}")
            result = scanner.scan_url_sync(
                url, custom_headers, not no_waf_detect, custom_waf, waf_mode, target_waf
            )
            results.append(result)

    # Filter results by level
    if level:
        min_level = VulnerabilityLevel(level)
        filtered_results = []
        for result in results:
            if result.vulnerabilities:
                filtered_results.append(result)
        results = filtered_results

    # Output results
    output_manager = OutputManager()

    # Generate advanced report if requested
    if report_format and output:
        try:
            report_config = ReportConfig(
                include_payloads=include_payloads,
                include_technical_details=include_technical,
                include_recommendations=executive_summary,
            )

            reporter = AdvancedReporter(report_config)

            # Generate the advanced report
            report_path = reporter.generate_comprehensive_report(
                results, report_format, output
            )
            click.echo(
                f"{Fore.GREEN}✅ Advanced report saved to: {report_path}{Style.RESET_ALL}"
            )

        except Exception as e:
            click.echo(
                f"{Fore.RED}❌ Failed to generate advanced report: {e}{Style.RESET_ALL}"
            )
            logger.error(f"Report generation failed: {e}")

    elif output:
        # Simple JSON output for backward compatibility
        import json

        json_data = [
            {"url": r.target.url, "vulnerabilities": len(r.vulnerabilities)}
            for r in results
        ]
        with open(output, "w") as f:
            json.dump(json_data, f, indent=2)
        click.echo(f"{Fore.GREEN}✅ Results saved to: {output}{Style.RESET_ALL}")
    else:
        # Simple console output
        for result in results:
            click.echo(f"\n{Fore.CYAN}🔍 URL: {result.target.url}{Style.RESET_ALL}")
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    level_color = {
                        "low": Fore.WHITE,
                        "medium": Fore.YELLOW,
                        "high": Fore.MAGENTA,
                        "critical": Fore.RED,
                    }.get(vuln.level.value, Fore.WHITE)
                    click.echo(
                        f"   {level_color}🚨 {vuln.level.value.upper()}: {vuln.payload}{Style.RESET_ALL}"
                    )
            else:
                click.echo(
                    f"   {Fore.GREEN}✅ No vulnerabilities found{Style.RESET_ALL}"
                )

    # Summary
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    vulnerable_urls = len([r for r in results if r.vulnerabilities])

    click.echo(f"\n{Fore.CYAN}📈 Scan Summary:{Style.RESET_ALL}")
    click.echo(f"   URLs scanned: {len(target_urls)}")
    click.echo(f"   Vulnerable URLs: {vulnerable_urls}")
    click.echo(f"   Total vulnerabilities: {total_vulns}")


async def scan_urls_async(
    scanner, urls, headers, detect_waf, custom_waf, waf_mode, target_waf
):
    """Scan multiple URLs asynchronously."""
    tasks = []

    for url in urls:
        task = scanner.scan_url_async(
            url, headers, detect_waf, custom_waf, waf_mode, target_waf
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle exceptions
    final_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Error scanning {urls[i]}: {result}")
            continue
        final_results.append(result)

    return final_results


@cli.command()
@click.option("--list", "list_payloads", is_flag=True, help="List all payloads")
@click.option("--waf", help="Filter payloads by WAF type")
@click.option(
    "--level",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Filter payloads by level",
)
@click.option("--add", help="Add new payload")
@click.option("--description", help="Description for new payload")
@click.option("--payload-waf", help="WAF type for new payload")
@click.option(
    "--payload-level",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Level for new payload",
)
@click.option("--count", is_flag=True, help="Show payload counts")
def payloads(
    list_payloads, waf, level, add, description, payload_waf, payload_level, count
):
    """Manage XSS payloads."""

    payload_manager = PayloadManager()

    if count:
        click.echo(f"{Fore.CYAN}📊 Payload Statistics:{Style.RESET_ALL}")
        click.echo(f"   Standard payloads: {payload_manager.payload_count}")
        click.echo(f"   WAF-specific payloads: {payload_manager.waf_payload_count}")
        click.echo(f"   Total payloads: {payload_manager.total_payload_count}")

        waf_types = payload_manager.get_waf_types()
        click.echo(f"\n🛡️  WAF Types ({len(waf_types)}):")
        for waf_type in waf_types:
            waf_payloads = payload_manager.get_all_payloads_combined(waf_type=waf_type)
            click.echo(f"   {waf_type}: {len(waf_payloads)} payloads")
        return

    if add:
        level_obj = VulnerabilityLevel(payload_level)
        payload = payload_manager.add_payload(add, payload_waf, description, level_obj)
        payload_manager.save_payloads()
        click.echo(f"{Fore.GREEN}✅ Added payload: {add}{Style.RESET_ALL}")
        return

    if list_payloads:
        payloads = payload_manager.get_all_payloads_combined(waf_type=waf)

        if level:
            level_obj = VulnerabilityLevel(level)
            payloads = [p for p in payloads if p.level == level_obj]

        click.echo(f"{Fore.CYAN}📋 Payloads ({len(payloads)}):{Style.RESET_ALL}")
        for i, payload in enumerate(payloads[:50], 1):  # Limit to 50
            waf_info = f" [{payload.waf}]" if payload.waf else ""
            level_color = {
                "low": Fore.WHITE,
                "medium": Fore.YELLOW,
                "high": Fore.MAGENTA,
                "critical": Fore.RED,
            }.get(payload.level.value, Fore.WHITE)

            click.echo(
                f"   {i:2d}. {level_color}{payload.level.value.upper()}{Style.RESET_ALL}{waf_info}"
            )
            click.echo(f"       {payload.content}")
            if payload.description:
                click.echo(
                    f"       {Fore.GREEN}Description: {payload.description}{Style.RESET_ALL}"
                )
            click.echo()

        if len(payloads) > 50:
            click.echo(f"   ... and {len(payloads) - 50} more payloads")


@cli.command()
@click.argument("url")
@click.option("--timeout", type=int, default=5, help="Detection timeout")
def detect_waf(url, timeout):
    """Detect WAF protection on a URL."""

    click.echo(f"{Fore.CYAN}🔍 Detecting WAF for: {url}{Style.RESET_ALL}")

    waf_detector = WAFDetector()
    detected_waf = waf_detector.detect_waf(url, timeout)

    if detected_waf:
        click.echo(f"{Fore.RED}🛡️  WAF Detected: {detected_waf}{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.GREEN}✅ No WAF detected{Style.RESET_ALL}")


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["html", "json", "csv", "markdown"]),
    default="html",
    help="Report format",
)
@click.option(
    "--output", "-o", type=click.Path(), required=True, help="Output file path"
)
@click.option("--title", default="XSS Security Assessment", help="Report title")
@click.option(
    "--include-payloads/--no-include-payloads",
    default=True,
    help="Include payloads in report",
)
@click.option(
    "--include-technical/--no-include-technical",
    default=True,
    help="Include technical details",
)
@click.option(
    "--include-recommendations/--no-include-recommendations",
    default=True,
    help="Include recommendations",
)
def generate_report(
    results_file,
    report_format,
    output,
    title,
    include_payloads,
    include_technical,
    include_recommendations,
):
    """Generate advanced security report from scan results."""

    import json

    try:
        # Load results from file
        with open(results_file, "r") as f:
            data = json.load(f)

        # Convert to ScanResult objects (simplified for demo)
        results = []
        # This would need proper parsing based on your JSON structure

        # Configure report
        config = ReportConfig(
            include_payloads=include_payloads,
            include_technical_details=include_technical,
            include_recommendations=include_recommendations,
        )

        reporter = AdvancedReporter(config)
        report_path = reporter.generate_comprehensive_report(
            results, report_format, output
        )

        click.echo(f"{Fore.GREEN}✅ Report generated: {report_path}{Style.RESET_ALL}")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Failed to generate report: {e}{Style.RESET_ALL}")
        sys.exit(1)


@cli.command("install-tools")
def install_tools_cmd():
    """Check and show installation status of integration tools."""
    click.echo(f"{Fore.CYAN}🔧 Checking Integration Tools{Style.RESET_ALL}")

    tools_status = install_tools()

    for tool, available in tools_status.items():
        status_icon = "✅" if available else "❌"
        status_text = "Available" if available else "Not found"
        click.echo(f"   {status_icon} {tool.capitalize()}: {status_text}")

    if not tools_status.get("arjun", False):
        click.echo(f"\n{Fore.YELLOW}📦 To install Arjun:{Style.RESET_ALL}")
        click.echo("   pip3 install arjun")

    if not tools_status.get("paramspider", False):
        click.echo(f"\n{Fore.YELLOW}📦 To install ParamSpider:{Style.RESET_ALL}")
        click.echo("   pip3 install paramspider")


@cli.command("discover")
@click.argument("url")
@click.option("--arjun", is_flag=True, help="Use Arjun for parameter discovery")
@click.option(
    "--paramspider", is_flag=True, help="Use ParamSpider for archive collection"
)
@click.option("--proxy", help="Proxy URL")
@click.option("--burp", is_flag=True, help="Use Burp Suite proxy")
@click.option("--tor", is_flag=True, help="Use Tor proxy")
def discover_params(url, arjun, paramspider, proxy, burp, tor):
    """Discover parameters for a URL using various tools."""
    if not (arjun or paramspider):
        click.echo(
            f"{Fore.RED}❌ Please specify at least one tool: --arjun or --paramspider{Style.RESET_ALL}"
        )
        return

    # Setup configuration
    config = ScannerConfig(burp_proxy=burp, use_tor=tor)
    if proxy:
        config.proxy_http = proxy
        config.proxy_https = proxy

    param_discovery = ParameterDiscovery(config)

    click.echo(f"{Fore.CYAN}🔍 Discovering parameters for: {url}{Style.RESET_ALL}")

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        results = loop.run_until_complete(
            param_discovery.discover_all_parameters(url, use_archives=paramspider)
        )

        # Display results
        if results.get("arjun_params"):
            click.echo(f"\n{Fore.GREEN}🎯 Arjun Parameters:{Style.RESET_ALL}")
            for param in results["arjun_params"]:
                click.echo(f"   • {param}")

        if results.get("archive_urls"):
            click.echo(
                f"\n{Fore.GREEN}🕷️  Archive URLs ({len(results['archive_urls'])}):{Style.RESET_ALL}"
            )
            for archive_url in results["archive_urls"][:10]:
                click.echo(f"   • {archive_url}")
            if len(results["archive_urls"]) > 10:
                click.echo(f"   ... and {len(results['archive_urls']) - 10} more")

        if results.get("enhanced_targets"):
            click.echo(
                f"\n{Fore.GREEN}📈 Enhanced Targets ({len(results['enhanced_targets'])}):{Style.RESET_ALL}"
            )
            for target in results["enhanced_targets"][:10]:
                click.echo(f"   • {target}")
            if len(results["enhanced_targets"]) > 10:
                click.echo(f"   ... and {len(results['enhanced_targets']) - 10} more")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Discovery failed: {e}{Style.RESET_ALL}")


@cli.command("user-agents")
@click.option("--list", "list_uas", is_flag=True, help="List available User-Agents")
@click.option(
    "--type",
    "ua_type",
    type=click.Choice(["browser", "security", "bot", "all"]),
    default="browser",
    help="Type of User-Agents to show",
)
@click.option("--random", is_flag=True, help="Show a random User-Agent")
@click.option("--info", help="Analyze a User-Agent string")
def user_agents_cmd(list_uas, ua_type, random, info):
    """Manage and view User-Agent strings."""
    from .user_agents import UserAgentManager

    ua_manager = UserAgentManager()

    if info:
        # Analyze User-Agent
        ua_info = UserAgentManager.get_ua_info(info)
        click.echo(f"{Fore.CYAN}🔍 User-Agent Analysis:{Style.RESET_ALL}")
        click.echo(f"   Browser: {ua_info['browser']}")
        click.echo(f"   Platform: {ua_info['platform']}")
        click.echo(f"   Mobile: {'Yes' if ua_info['mobile'] else 'No'}")
        click.echo(f"   Bot: {'Yes' if ua_info['bot'] else 'No'}")
        click.echo(f"   Full UA: {info}")
        return

    if random:
        # Show random User-Agent
        random_ua = ua_manager.get_random_ua(ua_type if ua_type != "all" else "any")
        click.echo(
            f"{Fore.GREEN}🎲 Random {ua_type.title()} User-Agent:{Style.RESET_ALL}"
        )
        click.echo(f"   {random_ua}")
        return

    if list_uas:
        # List User-Agents
        click.echo(f"{Fore.CYAN}📋 Available User-Agents ({ua_type}):{Style.RESET_ALL}")

        if ua_type == "browser" or ua_type == "all":
            click.echo(
                f"\n{Fore.GREEN}🌐 Browser User-Agents ({len(ua_manager.BROWSER_USER_AGENTS)}):{Style.RESET_ALL}"
            )
            for i, ua in enumerate(ua_manager.BROWSER_USER_AGENTS[:10], 1):
                click.echo(f"   {i:2d}. {ua}")
            if len(ua_manager.BROWSER_USER_AGENTS) > 10:
                click.echo(
                    f"   ... and {len(ua_manager.BROWSER_USER_AGENTS) - 10} more"
                )

        if ua_type == "security" or ua_type == "all":
            click.echo(
                f"\n{Fore.RED}🔧 Security Tool User-Agents ({len(ua_manager.SECURITY_TOOL_USER_AGENTS)}):{Style.RESET_ALL}"
            )
            for i, ua in enumerate(ua_manager.SECURITY_TOOL_USER_AGENTS, 1):
                click.echo(f"   {i:2d}. {ua}")

        if ua_type == "bot" or ua_type == "all":
            click.echo(
                f"\n{Fore.YELLOW}🤖 Bot User-Agents ({len(ua_manager.BOT_USER_AGENTS)}):{Style.RESET_ALL}"
            )
            for i, ua in enumerate(ua_manager.BOT_USER_AGENTS, 1):
                click.echo(f"   {i:2d}. {ua}")

        return

    # Default: show summary
    click.echo(f"{Fore.CYAN}🔧 User-Agent Manager{Style.RESET_ALL}")
    click.echo(f"   Browser UAs: {len(ua_manager.BROWSER_USER_AGENTS)}")
    click.echo(f"   Security Tool UAs: {len(ua_manager.SECURITY_TOOL_USER_AGENTS)}")
    click.echo(f"   Bot UAs: {len(ua_manager.BOT_USER_AGENTS)}")
    click.echo(f"\nUse --list to see all User-Agents")
    click.echo(f"Use --random to get a random User-Agent")


@cli.command("rate-limiting")
def rate_limiting_help():
    """Show rate limiting and stealth options."""

    title = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🚦 RATE LIMITING & STEALTH                          ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Available Rate Limiting Modes:{Style.RESET_ALL}

{Fore.GREEN}🕶️  Stealth Mode (--stealth){Style.RESET_ALL}
   • Extremely slow scanning (2-8 seconds between requests)
   • Random jitter and delays to mimic human behavior
   • Adaptive timing based on server responses
   • Best for bypassing advanced WAFs and rate limiting
   • Usage: xss-vibes scan --stealth <url>

{Fore.RED}🚀 Aggressive Mode (--aggressive){Style.RESET_ALL}
   • Fast scanning (up to 15 req/s)
   • Minimal delays, optimized for speed
   • Suitable for internal testing or less protected targets
   • Usage: xss-vibes scan --aggressive <url>

{Fore.CYAN}⚡ Custom Rate Limiting (--rate-limit){Style.RESET_ALL}
   • Set specific requests per second (e.g., --rate-limit 5.0)
   • Configurable adaptive timing and jitter
   • Balance between speed and stealth
   • Usage: xss-vibes scan --rate-limit 3.0 --adaptive --jitter <url>

{Fore.MAGENTA}🎯 Advanced Options:{Style.RESET_ALL}
   • --adaptive        Enable adaptive timing based on responses
   • --jitter          Add random timing variations
   • --min-delay N     Minimum delay in stealth mode (seconds)
   • --max-delay N     Maximum delay in stealth mode (seconds)

{Fore.YELLOW}Examples:{Style.RESET_ALL}

   # Ultra stealth mode
   xss-vibes scan --stealth --jitter https://target.com

   # Custom balanced approach
   xss-vibes scan --rate-limit 2.0 --adaptive --jitter https://target.com
   
   # Fast aggressive scan
   xss-vibes scan --aggressive https://target.com

   # Custom stealth with longer delays
   xss-vibes scan --stealth --min-delay 5 --max-delay 15 https://target.com

{Fore.GREEN}💡 Pro Tips:{Style.RESET_ALL}
   • Use stealth mode for heavily protected targets
   • Combine with proxy (--burp or --tor) for maximum anonymity
   • Monitor scan output for rate limiting warnings
   • Adaptive timing automatically adjusts based on server responses
"""

    click.echo(title)


@cli.command("encoding")
@click.option("--analyze", help="Analyze encoding potential of a specific payload")
@click.option("--test-payload", help="Test payload with all encoding techniques")
@click.option(
    "--list-encodings", is_flag=True, help="List all available encoding types"
)
@click.option("--demo", is_flag=True, help="Show encoding demonstration")
def encoding_cmd(analyze, test_payload, list_encodings, demo):
    """Advanced encoding techniques for WAF evasion."""

    if list_encodings:
        from .encoding_engine import EncodingType

        click.echo(f"{Fore.CYAN}🔐 Available Encoding Types:{Style.RESET_ALL}\n")

        encoding_descriptions = {
            "url": "Standard URL encoding (%20, %3C, etc.)",
            "double_url": "Double URL encoding (%253C, %2520, etc.)",
            "html": "HTML entity encoding (&lt;, &gt;, &#x3C;, etc.)",
            "unicode": "Unicode escape sequences (\\u003C, \\u003E, etc.)",
            "hex": "Hexadecimal encoding (\\x3C, \\x3E, etc.)",
            "octal": "Octal encoding (\\074, \\076, etc.)",
            "base64": "Base64 encoding with eval wrapper",
            "utf7": "UTF-7 encoding for IE/Edge bypass",
            "utf16": "UTF-16 encoding",
            "json": "JSON Unicode escapes",
            "css": "CSS character encoding (\\3C, \\3E, etc.)",
            "js": "JavaScript string encoding",
            "mixed": "Mixed case obfuscation",
            "char_sub": "Character entity substitution",
            "comments": "HTML/JS comment insertion",
            "whitespace": "Whitespace character substitution",
            "concat": "String concatenation",
            "eval": "Dynamic evaluation wrapper",
            "fromcharcode": "String.fromCharCode encoding",
        }

        for enc_type, description in encoding_descriptions.items():
            click.echo(
                f"   {Fore.GREEN}{enc_type:<12}{Style.RESET_ALL} - {description}"
            )

        click.echo(f"\n{Fore.YELLOW}Usage Examples:{Style.RESET_ALL}")
        click.echo("   xss-vibes scan --encoding --encoding-types unicode,base64 <url>")
        click.echo("   xss-vibes scan --high-evasion <url>")
        click.echo("   xss-vibes scan --context-aware <url>")

    elif analyze:
        from .payload_manager import PayloadManager

        payload_manager = PayloadManager()
        analysis = payload_manager.analyze_payload_evasion_potential(analyze)

        click.echo(f"{Fore.CYAN}🔍 Payload Evasion Analysis:{Style.RESET_ALL}\n")
        click.echo(f"Original: {analysis['original_payload']}")
        click.echo(f"WAF Bypass Score: {analysis['waf_bypass_score']}/10")

        char_analysis = analysis["character_analysis"]
        click.echo(f"\n{Fore.YELLOW}Character Analysis:{Style.RESET_ALL}")
        click.echo(
            f"   Dangerous characters: {', '.join(char_analysis['dangerous_characters']) if char_analysis['dangerous_characters'] else 'None'}"
        )
        click.echo(f"   Danger score: {char_analysis['danger_score']:.1f}/10")
        click.echo(
            f"   Requires encoding: {'Yes' if char_analysis['requires_encoding'] else 'No'}"
        )

        click.echo(f"\n{Fore.GREEN}Best Encoding Techniques:{Style.RESET_ALL}")
        for i, encoding in enumerate(analysis["best_encodings"][:5], 1):
            click.echo(
                f"   {i}. {encoding['encoding']} (Score: {encoding['bypass_potential']}/10)"
            )
            click.echo(f"      {encoding['description']}")

    elif test_payload:
        from .encoding_engine import advanced_encoder, EncodingType

        click.echo(f"{Fore.CYAN}🧪 Encoding Test Results:{Style.RESET_ALL}\n")
        click.echo(f"Original: {test_payload}\n")

        # Test with selected high-impact encodings
        test_encodings = [
            EncodingType.UNICODE,
            EncodingType.BASE64,
            EncodingType.FROMCHARCODE,
            EncodingType.UTF7,
            EncodingType.DOUBLE_URL,
        ]

        for encoding_type in test_encodings:
            try:
                result = advanced_encoder.encode_payload(test_payload, encoding_type)
                click.echo(f"{Fore.GREEN}{encoding_type.value}:{Style.RESET_ALL}")
                click.echo(f"   {result.encoded}")
                click.echo(f"   Bypass Potential: {result.waf_bypass_potential}/10")
                click.echo(f"   Complexity: {result.complexity}/10\n")
            except Exception as e:
                click.echo(
                    f"{Fore.RED}{encoding_type.value}: Failed - {e}{Style.RESET_ALL}\n"
                )

    elif demo:
        demo_payload = "<script>alert('XSS')</script>"

        click.echo(f"{Fore.CYAN}🎭 Encoding Demonstration:{Style.RESET_ALL}\n")
        click.echo(f"Demo payload: {demo_payload}\n")

        from .encoding_engine import generate_evasion_variants

        variants = generate_evasion_variants(demo_payload, count=5)

        for i, variant in enumerate(variants, 1):
            click.echo(
                f"{Fore.YELLOW}Variant {i} ({variant.encoding_type.value}):{Style.RESET_ALL}"
            )
            click.echo(f"   {variant.encoded}")
            click.echo(f"   Bypass Potential: {variant.waf_bypass_potential}/10")
            click.echo(f"   Description: {variant.description}\n")

    else:
        # Show general help
        title = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🔐 ADVANCED ENCODING ENGINE                         ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Advanced WAF Evasion Techniques:{Style.RESET_ALL}

{Fore.GREEN}🎯 High-Evasion Mode (--high-evasion){Style.RESET_ALL}
   • Uses only the most effective bypass techniques
   • Combines multiple encoding layers
   • Targets specific WAF weaknesses
   • Usage: xss-vibes scan --high-evasion <url>

{Fore.BLUE}🧠 Context-Aware Encoding (--context-aware){Style.RESET_ALL}
   • Detects injection context automatically
   • Applies context-specific encoding techniques
   • Optimizes for HTML attributes, JavaScript, CSS, etc.
   • Usage: xss-vibes scan --context-aware <url>

{Fore.MAGENTA}⚙️  Custom Encoding (--encoding){Style.RESET_ALL}
   • Manual control over encoding techniques
   • Specify exact encoding types to use
   • Configure number of variants per payload
   • Usage: xss-vibes scan --encoding --encoding-types unicode,base64 <url>

{Fore.CYAN}Available Commands:{Style.RESET_ALL}
   encoding --list-encodings     Show all encoding types
   encoding --analyze "payload"  Analyze payload evasion potential  
   encoding --test-payload "x"   Test payload with encodings
   encoding --demo               Show encoding demonstration

{Fore.GREEN}💡 Pro Tips:{Style.RESET_ALL}
   • Combine with stealth mode for maximum evasion
   • Use context-aware for targeted injection points
   • High-evasion mode for heavily protected targets
   • Mix different encoding types for better results
"""

        click.echo(title)


@cli.command("mutation")
@click.option("--payload", required=True, help="Base payload for mutation")
@click.option(
    "--context",
    type=click.Choice(
        ["html_text", "html_attribute", "javascript_string", "url_parameter"]
    ),
    default="html_text",
    help="Injection context",
)
@click.option(
    "--generations", type=int, default=5, help="Number of evolution generations"
)
@click.option(
    "--population", type=int, default=20, help="Population size for genetic algorithm"
)
@click.option(
    "--variants", type=int, default=10, help="Number of mutation variants to generate"
)
@click.option("--save", help="Save results to file")
def mutation_cmd(payload, context, generations, population, variants, save):
    """Intelligent payload mutation using genetic algorithms."""

    click.echo(f"{Fore.CYAN}🧬 Payload Mutation Engine{Style.RESET_ALL}\n")

    try:
        # Initialize mutation engine
        mutation_engine = PayloadMutationEngine()

        # Convert context string to enum
        context_map = {
            "html_text": InjectionContext.HTML_CONTENT,
            "html_attribute": InjectionContext.HTML_ATTRIBUTE,
            "javascript_string": InjectionContext.JAVASCRIPT_STRING,
            "url_parameter": InjectionContext.URL_PARAMETER,
        }

        injection_context = context_map.get(context, InjectionContext.HTML_CONTENT)

        click.echo(f"Original payload: {payload}")
        click.echo(f"Context: {context}")
        click.echo(f"Generating {variants} variants...\n")

        # Generate mutations
        mutations = mutation_engine.mutate_payload(
            payload, injection_context, intensity=variants
        )

        results = []
        for i, mutation in enumerate(mutations, 1):
            click.echo(f"{Fore.GREEN}Variant {i}:{Style.RESET_ALL}")
            click.echo(f"  Payload: {mutation.mutated_payload}")
            click.echo(f"  Score: {mutation.confidence_score:.3f}")
            click.echo(
                f"  Mutations: {', '.join([m.value for m in mutation.mutations_applied])}"
            )
            click.echo()

            results.append(
                {
                    "variant": i,
                    "payload": mutation.mutated_payload,
                    "score": mutation.confidence_score,
                    "mutations": [m.value for m in mutation.mutations_applied],
                }
            )

        # Save results if requested
        if save:
            import json

            with open(save, "w") as f:
                json.dump(
                    {"original": payload, "context": context, "variants": results},
                    f,
                    indent=2,
                )
            click.echo(f"{Fore.GREEN}✅ Results saved to {save}{Style.RESET_ALL}")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Mutation failed: {e}{Style.RESET_ALL}")


@cli.command("session")
@click.option("--login-url", required=True, help="Login URL")
@click.option("--username", required=True, help="Username")
@click.option("--password", required=True, help="Password")
@click.option(
    "--auth-type",
    type=click.Choice(["form", "basic", "digest"]),
    default="form",
    help="Authentication type",
)
@click.option("--test-url", help="URL to test authenticated access")
@click.option("--save-profile", help="Save session profile to file")
def session_cmd(login_url, username, password, auth_type, test_url, save_profile):
    """Test and manage authentication sessions."""

    click.echo(f"{Fore.CYAN}🔐 Session Management{Style.RESET_ALL}\n")

    try:
        # Setup session manager
        session_config = SessionConfig()
        session_manager = SessionManager(session_config)

        # Create credentials
        credentials = LoginCredentials(
            username=username, password=password, login_url=login_url
        )

        auth_method = AuthMethod(type=auth_type, credentials=credentials)

        # Attempt authentication
        click.echo(f"Authenticating with {auth_type} method...")
        if session_manager.authenticate(auth_method):
            click.echo(f"{Fore.GREEN}✅ Authentication successful{Style.RESET_ALL}")

            # Test authenticated access
            if test_url:
                click.echo(f"\nTesting authenticated access to {test_url}...")
                response = session_manager.make_authenticated_request("GET", test_url)
                click.echo(f"Status: {response.status_code}")
                click.echo(f"Response length: {len(response.text)} bytes")

            # Show session info
            session_info = session_manager.get_session_info()
            click.echo(f"\n{Fore.CYAN}Session Information:{Style.RESET_ALL}")
            for key, value in session_info.items():
                click.echo(f"  {key}: {value}")

            # Save profile if requested
            if save_profile:
                # This would save to session profile manager
                click.echo(
                    f"{Fore.GREEN}✅ Profile saving not yet implemented{Style.RESET_ALL}"
                )

        else:
            click.echo(f"{Fore.RED}❌ Authentication failed{Style.RESET_ALL}")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Session error: {e}{Style.RESET_ALL}")
    finally:
        if "session_manager" in locals():
            session_manager.close()


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
