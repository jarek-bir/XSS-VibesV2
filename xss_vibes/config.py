"""Configuration management for XSS Vibes scanner."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, TYPE_CHECKING
import json

if TYPE_CHECKING:
    from .rate_limit import RateLimiter


@dataclass
class ScannerConfig:
    """Configuration class for the XSS scanner."""

    max_threads: int = 7
    max_allowed_threads: int = 10
    default_timeout: int = 10
    verify_ssl: bool = False
    crawl_depth: int = 4

    # Proxy configuration
    proxy_http: Optional[str] = None
    proxy_https: Optional[str] = None
    use_tor: bool = False
    burp_proxy: bool = False

    # User-Agent configuration
    random_user_agent: bool = False
    user_agent_type: str = "browser"  # browser, security, bot, any
    rotate_user_agent: bool = False
    custom_user_agent: Optional[str] = None

    # File paths
    payloads_file: Path = Path(__file__).parent / "data" / "payloads.json"
    waf_list_file: Path = Path(__file__).parent / "data" / "waf_list.txt"

    # Default headers
    default_headers: Optional[Dict[str, str]] = None

    # Rate limiting
    rate_limiter: Optional["RateLimiter"] = None

    def __post_init__(self):
        if self.default_headers is None:
            self.default_headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            }

        # Set up proxy configurations
        if self.burp_proxy:
            self.proxy_http = "http://127.0.0.1:8080"
            self.proxy_https = "http://127.0.0.1:8080"
        elif self.use_tor:
            self.proxy_http = "socks5://127.0.0.1:9050"
            self.proxy_https = "socks5://127.0.0.1:9050"

        # Set up User-Agent
        if self.custom_user_agent:
            self.default_headers["User-Agent"] = self.custom_user_agent
        elif self.random_user_agent:
            from .user_agents import get_random_user_agent

            self.default_headers["User-Agent"] = get_random_user_agent(
                self.user_agent_type
            )

    def get_user_agent(self) -> str:
        """Get User-Agent for requests."""
        if self.default_headers is None:
            self.default_headers = {}

        if self.random_user_agent and self.rotate_user_agent:
            from .user_agents import rotate_user_agent

            ua = rotate_user_agent(self.user_agent_type)
            self.default_headers["User-Agent"] = ua
            return ua
        return self.default_headers.get("User-Agent", "")

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration as dictionary for requests/aiohttp."""
        if self.proxy_http or self.proxy_https:
            proxy_dict = {}
            if self.proxy_http:
                proxy_dict["http"] = self.proxy_http
            if self.proxy_https:
                proxy_dict["https"] = self.proxy_https
            elif self.proxy_http:
                proxy_dict["https"] = self.proxy_http
            return proxy_dict
        return None

    @classmethod
    def from_file(cls, config_path: Path) -> "ScannerConfig":
        """Load configuration from JSON file."""
        if config_path.exists():
            with open(config_path, "r") as f:
                config_data = json.load(f)
            return cls(**config_data)
        return cls()

    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file."""
        config_data = {
            "max_threads": self.max_threads,
            "max_allowed_threads": self.max_allowed_threads,
            "default_timeout": self.default_timeout,
            "verify_ssl": self.verify_ssl,
            "crawl_depth": self.crawl_depth,
            "proxy_http": self.proxy_http,
            "proxy_https": self.proxy_https,
            "use_tor": self.use_tor,
            "burp_proxy": self.burp_proxy,
            "random_user_agent": self.random_user_agent,
            "user_agent_type": self.user_agent_type,
            "rotate_user_agent": self.rotate_user_agent,
            "custom_user_agent": self.custom_user_agent,
            "default_headers": self.default_headers,
        }
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)
