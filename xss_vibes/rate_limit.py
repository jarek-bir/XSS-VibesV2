"""Rate limiting and stealth mode for XSS scanner."""

import asyncio
import secrets  # Secure random generator
import time
from typing import Optional, Tuple
from dataclasses import dataclass
import logging


logger = logging.getLogger("xss_vibes.rate_limit")


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    # Basic rate limiting
    requests_per_second: float = 5.0
    max_burst: int = 10

    # Stealth mode settings
    stealth_mode: bool = False
    min_delay: float = 2.0
    max_delay: float = 8.0

    # Jitter settings
    jitter_enabled: bool = False
    jitter_min: float = 0.1
    jitter_max: float = 1.0

    # Adaptive timing
    adaptive_timing: bool = False
    error_backoff_multiplier: float = 2.0
    success_speedup_factor: float = 0.9


class RateLimiter:
    """Advanced rate limiter with stealth capabilities."""

    def __init__(self, config: RateLimitConfig):
        """Initialize rate limiter."""
        self.config = config
        self.last_request_time = 0.0
        self.request_count = 0
        self.burst_count = 0
        self.current_delay = 1.0 / config.requests_per_second
        self.consecutive_errors = 0
        self.consecutive_successes = 0

        # Token bucket for burst handling
        self.tokens = config.max_burst
        self.last_token_update = time.time()

        logger.info(
            f"Rate limiter initialized: {config.requests_per_second} req/s, stealth: {config.stealth_mode}"
        )

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        current_time = time.time()

        if self.config.stealth_mode:
            await self._stealth_delay()
        else:
            await self._normal_rate_limit()

        # Add jitter if enabled
        if self.config.jitter_enabled:
            jitter = secrets.SystemRandom().uniform(
                self.config.jitter_min, self.config.jitter_max
            )
            await asyncio.sleep(jitter)
            logger.debug(f"Applied jitter: {jitter:.2f}s")

        self.last_request_time = time.time()
        self.request_count += 1

    async def _stealth_delay(self) -> None:
        """Apply stealth mode delays."""
        base_delay = secrets.SystemRandom().uniform(
            self.config.min_delay, self.config.max_delay
        )

        # Add adaptive timing
        if self.config.adaptive_timing:
            if self.consecutive_errors > 0:
                base_delay *= (
                    self.config.error_backoff_multiplier**self.consecutive_errors
                )
            elif self.consecutive_successes > 5:
                base_delay *= self.config.success_speedup_factor

        logger.debug(f"Stealth delay: {base_delay:.2f}s")
        await asyncio.sleep(base_delay)

    async def _normal_rate_limit(self) -> None:
        """Apply normal rate limiting using token bucket."""
        current_time = time.time()

        # Refill tokens
        time_passed = current_time - self.last_token_update
        self.tokens = min(
            self.config.max_burst,
            self.tokens + (time_passed * self.config.requests_per_second),
        )
        self.last_token_update = current_time

        # Check if we have tokens
        if self.tokens < 1:
            wait_time = (1 - self.tokens) / self.config.requests_per_second
            logger.debug(f"Rate limit: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
            self.tokens = 0
        else:
            self.tokens -= 1

        # Ensure minimum delay between requests
        min_interval = 1.0 / self.config.requests_per_second
        time_since_last = current_time - self.last_request_time

        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            await asyncio.sleep(wait_time)

    def report_success(self) -> None:
        """Report a successful request for adaptive timing."""
        self.consecutive_errors = 0
        self.consecutive_successes += 1

        if self.config.adaptive_timing and self.consecutive_successes % 5 == 0:
            logger.debug(
                f"Adaptive timing: {self.consecutive_successes} consecutive successes"
            )

    def report_error(self, error_type: str = "general") -> None:
        """Report an error for adaptive timing."""
        self.consecutive_successes = 0
        self.consecutive_errors += 1

        if self.config.adaptive_timing:
            logger.warning(
                f"Adaptive timing: {self.consecutive_errors} consecutive errors ({error_type})"
            )

            # Special handling for different error types
            if error_type in ["rate_limited", "blocked", "captcha"]:
                self.consecutive_errors += 2  # More aggressive backoff

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        current_time = time.time()
        total_time = (
            current_time - self.last_request_time if self.request_count > 0 else 0
        )

        return {
            "total_requests": self.request_count,
            "total_time": total_time,
            "average_rate": self.request_count / total_time if total_time > 0 else 0,
            "current_delay": self.current_delay,
            "consecutive_errors": self.consecutive_errors,
            "consecutive_successes": self.consecutive_successes,
            "tokens_available": self.tokens,
        }


class StealthManager:
    """Advanced stealth techniques manager."""

    def __init__(self, rate_limiter: RateLimiter):
        """Initialize stealth manager."""
        self.rate_limiter = rate_limiter
        self.request_patterns = []
        self.last_user_agent_rotation = 0
        self.suspicious_responses = 0

    def analyze_response(
        self, response_status: int, response_headers: dict, response_time: float
    ) -> dict:
        """Analyze response for stealth indicators."""
        analysis = {
            "suspicious": False,
            "risk_level": "low",
            "indicators": [],
            "recommendations": [],
        }

        # Check for rate limiting indicators
        if response_status in [429, 503, 509]:
            analysis["suspicious"] = True
            analysis["risk_level"] = "high"
            analysis["indicators"].append(f"Rate limiting response: {response_status}")
            analysis["recommendations"].append("Increase delays between requests")

        # Check for WAF/security responses
        security_headers = ["cf-ray", "x-sucuri-id", "x-akamai-request-id", "server"]
        for header in security_headers:
            if header in [h.lower() for h in response_headers.keys()]:
                analysis["indicators"].append(f"Security header detected: {header}")

        # Check response time patterns
        if response_time > 10.0:
            analysis["indicators"].append("Unusually slow response time")
            analysis["recommendations"].append("Consider reducing request complexity")

        # Check for CAPTCHA or challenge pages
        content_indicators = response_headers.get("content-type", "").lower()
        if "challenge" in content_indicators or response_status == 403:
            analysis["suspicious"] = True
            analysis["risk_level"] = "critical"
            analysis["indicators"].append("Possible CAPTCHA or challenge page")
            analysis["recommendations"].append("Stop scanning and wait before resuming")

        return analysis

    def should_rotate_session(self) -> bool:
        """Determine if session should be rotated."""
        return (
            self.suspicious_responses > 3
            or len(self.request_patterns) > 100
            or time.time() - self.last_user_agent_rotation > 300  # 5 minutes
        )

    def get_stealth_recommendations(self) -> list:
        """Get stealth recommendations based on current state."""
        recommendations = []

        if self.suspicious_responses > 0:
            recommendations.append("Consider increasing delays between requests")

        if len(self.request_patterns) > 50:
            recommendations.append("Rotate User-Agent and session")

        if self.rate_limiter.consecutive_errors > 2:
            recommendations.append("Enable stealth mode or reduce request rate")

        return recommendations


class AdaptiveThrottler:
    """Adaptive throttling based on server responses."""

    def __init__(self, initial_rate: float = 5.0):
        """Initialize adaptive throttler."""
        self.current_rate = initial_rate
        self.min_rate = 0.1
        self.max_rate = 20.0
        self.response_times = []
        self.error_count = 0
        self.adjustment_factor = 1.2

    def adjust_rate(self, response_time: float, status_code: int) -> float:
        """Adjust rate based on response characteristics."""
        self.response_times.append(response_time)

        # Keep only recent response times
        if len(self.response_times) > 10:
            self.response_times = self.response_times[-10:]

        avg_response_time = sum(self.response_times) / len(self.response_times)

        # Adjust based on response time
        if avg_response_time > 5.0:  # Slow responses
            self.current_rate = max(
                self.min_rate, self.current_rate / self.adjustment_factor
            )
            logger.debug(
                f"Slowing down due to high response time: {avg_response_time:.2f}s"
            )

        elif (
            avg_response_time < 1.0 and status_code == 200
        ):  # Fast successful responses
            self.current_rate = min(self.max_rate, self.current_rate * 1.1)
            logger.debug(
                f"Speeding up due to good response time: {avg_response_time:.2f}s"
            )

        # Adjust based on status codes
        if status_code in [429, 503, 509]:  # Rate limiting
            self.current_rate = max(self.min_rate, self.current_rate / 2)
            self.error_count += 1
            logger.warning(
                f"Rate limited! Reducing rate to {self.current_rate:.2f} req/s"
            )

        elif status_code in range(200, 300):  # Success
            self.error_count = max(0, self.error_count - 1)

        return self.current_rate

    def get_delay(self) -> float:
        """Get current delay between requests."""
        base_delay = 1.0 / self.current_rate

        # Add error-based penalty
        if self.error_count > 0:
            base_delay *= 1.5 ** min(self.error_count, 5)

        return base_delay


# Factory functions for easy usage
def create_stealth_rate_limiter() -> RateLimiter:
    """Create a rate limiter configured for stealth mode."""
    config = RateLimitConfig(
        requests_per_second=0.5,  # Very slow
        stealth_mode=True,
        min_delay=3.0,
        max_delay=10.0,
        jitter_enabled=True,
        jitter_min=0.5,
        jitter_max=2.0,
        adaptive_timing=True,
    )
    return RateLimiter(config)


def create_normal_rate_limiter(requests_per_second: float = 5.0) -> RateLimiter:
    """Create a normal rate limiter."""
    config = RateLimitConfig(
        requests_per_second=requests_per_second,
        max_burst=10,
        jitter_enabled=True,
        adaptive_timing=True,
    )
    return RateLimiter(config)


def create_aggressive_rate_limiter() -> RateLimiter:
    """Create an aggressive rate limiter for fast scanning."""
    config = RateLimitConfig(
        requests_per_second=15.0,
        max_burst=25,
        jitter_enabled=False,
        adaptive_timing=True,
    )
    return RateLimiter(config)
