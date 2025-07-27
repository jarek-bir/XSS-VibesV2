"""HTTP client with proxy and User-Agent support."""

import asyncio
import aiohttp
import requests
from typing import Optional, Dict, Any, Tuple
import logging
import time
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

from .user_agents import ua_manager
from .rate_limit import RateLimiter, StealthManager, AdaptiveThrottler


logger = logging.getLogger("xss_vibes.http_client")


@dataclass
class ScannerConfig:
    """Basic configuration for HTTP client."""

    verify_ssl: bool = False
    default_timeout: int = 10
    proxy_url: Optional[str] = None
    user_agent_type: str = "browser"
    rate_limiter: Optional[RateLimiter] = None
    default_headers: Optional[Dict[str, str]] = None

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests."""
        if self.proxy_url:
            return {"http": self.proxy_url, "https": self.proxy_url}
        return None


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""

    status: int
    content: str
    headers: Dict[str, str]
    url: str
    error: Optional[str] = None
    response_time: float = 0.0


class AsyncHTTPClient:
    """Async HTTP client for XSS testing."""

    def __init__(self, config: ScannerConfig):
        """
        Initialize HTTP client.

        Args:
            config: Scanner configuration
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry."""
        # Setup proxy configuration
        proxy_dict = self.config.get_proxy_dict()

        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl, limit=100, ttl_dns_cache=300
        )

        timeout = aiohttp.ClientTimeout(total=self.config.default_timeout)

        # Create session with proxy support
        session_kwargs = {
            "connector": connector,
            "timeout": timeout,
            "headers": self.config.default_headers or {},
        }

        # Add proxy if configured
        if proxy_dict:
            # For aiohttp, we need to handle proxy per request
            # Store proxy info for later use
            self._proxy_url = proxy_dict
        else:
            self._proxy_url = None

        self.session = aiohttp.ClientSession(**session_kwargs)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Perform async GET request.

        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers

        Returns:
            HTTPResponse object
        """
        if not self.session:
            raise RuntimeError(
                "HTTP client not initialized - use async context manager"
            )

        # Apply rate limiting if configured
        if self.config.rate_limiter:
            await self.config.rate_limiter.acquire()

        start_time = time.time()

        try:
            request_headers = (self.config.default_headers or {}).copy()
            if headers:
                request_headers.update(headers)

            # Add User-Agent if not specified
            if "User-Agent" not in request_headers:
                request_headers["User-Agent"] = ua_manager.get_random_ua(
                    self.config.user_agent_type
                )

            # Setup request kwargs
            request_kwargs = {
                "params": params,
                "headers": request_headers,
                "ssl": self.config.verify_ssl,
            }

            # Add proxy if configured
            if hasattr(self, "_proxy_url") and self._proxy_url:
                request_kwargs["proxy"] = self._proxy_url

            async with self.session.get(url, **request_kwargs) as response:
                content = await response.text()
                response_time = time.time() - start_time

                result = HTTPResponse(
                    status=response.status,
                    content=content,
                    headers=dict(response.headers),
                    url=str(response.url),
                    response_time=response_time,
                )

                # Report success to rate limiter
                if self.config.rate_limiter:
                    self.config.rate_limiter.report_success()

                return result

        except asyncio.TimeoutError:
            logger.warning(f"Timeout for {url}")
            if self.config.rate_limiter:
                self.config.rate_limiter.report_error("timeout")
            return HTTPResponse(
                status=0,
                content="",
                headers={},
                url=url,
                error="Timeout",
                response_time=time.time() - start_time,
            )
        except Exception as e:
            logger.error(f"Request error for {url}: {e}")
            if self.config.rate_limiter:
                self.config.rate_limiter.report_error("connection_error")
            return HTTPResponse(
                status=0,
                content="",
                headers={},
                url=url,
                error=str(e),
                response_time=time.time() - start_time,
            )

    async def test_payload(
        self,
        base_url: str,
        param_name: str,
        payload: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Test a specific payload on a parameter.

        Args:
            base_url: Base URL without query parameters
            param_name: Parameter name to inject payload
            payload: XSS payload to test
            headers: Additional headers

        Returns:
            HTTPResponse object
        """
        # Parse original URL to get existing parameters
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query) if parsed.query else {}

        # Flatten existing parameters (take first value for each)
        params = {
            k: v[0] if isinstance(v, list) and v else str(v)
            for k, v in existing_params.items()
        }

        # Set the payload for the target parameter
        params[param_name] = payload

        # Construct clean URL without query string
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        return await self.get(clean_url, params=params, headers=headers)


class SyncHTTPClient:
    """Synchronous HTTP client for backward compatibility."""

    def __init__(self, config: ScannerConfig):
        """Initialize sync HTTP client."""
        self.config = config

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Perform synchronous GET request.

        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers

        Returns:
            HTTPResponse object
        """
        import requests

        try:
            request_headers = (self.config.default_headers or {}).copy()
            if headers:
                request_headers.update(headers)

            # Add User-Agent if not specified
            if "User-Agent" not in request_headers:
                request_headers["User-Agent"] = ua_manager.get_random_ua(
                    self.config.user_agent_type
                )

            # Setup request kwargs
            request_kwargs = {
                "params": params,
                "headers": request_headers,
                "timeout": self.config.default_timeout,
                "verify": self.config.verify_ssl,
            }

            # Add proxy if configured
            proxy_dict = self.config.get_proxy_dict()
            if proxy_dict:
                request_kwargs["proxies"] = proxy_dict

            response = requests.get(
                url, timeout=self.config.default_timeout, **request_kwargs
            )

            return HTTPResponse(
                status=response.status_code,
                content=response.text,
                headers=dict(response.headers),
                url=str(response.url),
            )

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout for {url}")
            return HTTPResponse(
                status=0, content="", headers={}, url=url, error="Timeout"
            )
        except Exception as e:
            logger.error(f"Request error for {url}: {e}")
            return HTTPResponse(status=0, content="", headers={}, url=url, error=str(e))
