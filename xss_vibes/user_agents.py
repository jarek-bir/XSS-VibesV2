"""User-Agent management for better blending with normal traffic."""

import random
from typing import List, Optional


class UserAgentManager:
    """Manages User-Agent strings for HTTP requests."""

    # Real browser User-Agents updated for 2025
    BROWSER_USER_AGENTS = [
        # Chrome (Windows)
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Chrome (macOS)
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Chrome (Linux)
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Firefox (Windows)
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        # Firefox (macOS)
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Firefox (Linux)
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari (macOS)
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        # Safari (iPhone)
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        # Edge (Windows)
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        # Opera
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        # Chrome Mobile (Android)
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        # Samsung Internet
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    ]

    # Security tool User-Agents (for stealth mode)
    SECURITY_TOOL_USER_AGENTS = [
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "Mozilla/5.0 (compatible; Nuclei - Open-source vulnerability scanner)",
        "curl/8.4.0",
        "python-requests/2.31.0",
        "sqlmap/1.7.11#stable (http://sqlmap.org)",
        "Mozilla/5.0 (compatible; OWASP ZAP)",
        "Burp Scanner",
        "Mozilla/5.0 (compatible; Nikto/2.5.0)",
    ]

    # API and bot User-Agents
    BOT_USER_AGENTS = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "Twitterbot/1.0",
        "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
        "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    ]

    def __init__(self):
        """Initialize User-Agent manager."""
        self.current_ua = None

    def get_random_browser_ua(self) -> str:
        """Get a random browser User-Agent."""
        return random.choice(self.BROWSER_USER_AGENTS)

    def get_random_security_tool_ua(self) -> str:
        """Get a random security tool User-Agent."""
        return random.choice(self.SECURITY_TOOL_USER_AGENTS)

    def get_random_bot_ua(self) -> str:
        """Get a random bot User-Agent."""
        return random.choice(self.BOT_USER_AGENTS)

    def get_random_ua(self, ua_type: str = "browser") -> str:
        """
        Get a random User-Agent of specified type.

        Args:
            ua_type: Type of User-Agent ('browser', 'security', 'bot', 'any')

        Returns:
            Random User-Agent string
        """
        if ua_type == "browser":
            return self.get_random_browser_ua()
        elif ua_type == "security":
            return self.get_random_security_tool_ua()
        elif ua_type == "bot":
            return self.get_random_bot_ua()
        elif ua_type == "any":
            all_uas = (
                self.BROWSER_USER_AGENTS
                + self.SECURITY_TOOL_USER_AGENTS
                + self.BOT_USER_AGENTS
            )
            return random.choice(all_uas)
        else:
            return self.get_random_browser_ua()

    def set_random_ua(self, ua_type: str = "browser") -> str:
        """
        Set and return a random User-Agent.

        Args:
            ua_type: Type of User-Agent to use

        Returns:
            Selected User-Agent string
        """
        self.current_ua = self.get_random_ua(ua_type)
        return self.current_ua

    def get_current_ua(self) -> Optional[str]:
        """Get currently set User-Agent."""
        return self.current_ua

    def rotate_ua(self, ua_type: str = "browser") -> str:
        """
        Rotate to a new random User-Agent.

        Args:
            ua_type: Type of User-Agent to rotate to

        Returns:
            New User-Agent string
        """
        old_ua = self.current_ua
        new_ua = self.get_random_ua(ua_type)

        # Ensure we get a different UA
        while new_ua == old_ua and len(self.BROWSER_USER_AGENTS) > 1:
            new_ua = self.get_random_ua(ua_type)

        self.current_ua = new_ua
        return new_ua

    def get_chrome_ua(self, platform: str = "windows") -> str:
        """
        Get a Chrome User-Agent for specific platform.

        Args:
            platform: Platform ('windows', 'macos', 'linux')

        Returns:
            Chrome User-Agent string
        """
        chrome_uas = [ua for ua in self.BROWSER_USER_AGENTS if "Chrome" in ua]

        if platform == "windows":
            platform_uas = [ua for ua in chrome_uas if "Windows" in ua]
        elif platform == "macos":
            platform_uas = [ua for ua in chrome_uas if "Macintosh" in ua]
        elif platform == "linux":
            platform_uas = [ua for ua in chrome_uas if "Linux" in ua]
        else:
            platform_uas = chrome_uas

        return (
            random.choice(platform_uas) if platform_uas else random.choice(chrome_uas)
        )

    def get_firefox_ua(self, platform: str = "windows") -> str:
        """
        Get a Firefox User-Agent for specific platform.

        Args:
            platform: Platform ('windows', 'macos', 'linux')

        Returns:
            Firefox User-Agent string
        """
        firefox_uas = [ua for ua in self.BROWSER_USER_AGENTS if "Firefox" in ua]

        if platform == "windows":
            platform_uas = [ua for ua in firefox_uas if "Windows" in ua]
        elif platform == "macos":
            platform_uas = [ua for ua in firefox_uas if "Macintosh" in ua]
        elif platform == "linux":
            platform_uas = [ua for ua in firefox_uas if "Linux" in ua]
        else:
            platform_uas = firefox_uas

        return (
            random.choice(platform_uas) if platform_uas else random.choice(firefox_uas)
        )

    def get_mobile_ua(self) -> str:
        """Get a random mobile User-Agent."""
        mobile_uas = [
            ua
            for ua in self.BROWSER_USER_AGENTS
            if any(keyword in ua for keyword in ["Mobile", "iPhone", "Android"])
        ]
        return random.choice(mobile_uas)

    @classmethod
    def get_ua_info(cls, user_agent: str) -> dict:
        """
        Extract information from User-Agent string.

        Args:
            user_agent: User-Agent string to analyze

        Returns:
            Dictionary with UA information
        """
        info = {
            "browser": "Unknown",
            "version": "Unknown",
            "platform": "Unknown",
            "mobile": False,
            "bot": False,
        }

        # Detect browser
        if "Chrome" in user_agent and "Edg" not in user_agent:
            info["browser"] = "Chrome"
        elif "Firefox" in user_agent:
            info["browser"] = "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            info["browser"] = "Safari"
        elif "Edg" in user_agent:
            info["browser"] = "Edge"
        elif "OPR" in user_agent:
            info["browser"] = "Opera"

        # Detect platform
        if "Windows" in user_agent:
            info["platform"] = "Windows"
        elif "Macintosh" in user_agent or "Mac OS X" in user_agent:
            info["platform"] = "macOS"
        elif "Linux" in user_agent:
            info["platform"] = "Linux"
        elif "Android" in user_agent:
            info["platform"] = "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            info["platform"] = "iOS"

        # Detect mobile
        info["mobile"] = any(
            keyword in user_agent for keyword in ["Mobile", "iPhone", "iPad", "Android"]
        )

        # Detect bot
        info["bot"] = any(
            keyword in user_agent
            for keyword in ["bot", "Bot", "crawler", "spider", "Spider"]
        )

        return info


# Global instance for easy access
ua_manager = UserAgentManager()


def get_random_user_agent(ua_type: str = "browser") -> str:
    """Convenience function to get random User-Agent."""
    return ua_manager.get_random_ua(ua_type)


def rotate_user_agent(ua_type: str = "browser") -> str:
    """Convenience function to rotate User-Agent."""
    return ua_manager.rotate_ua(ua_type)
