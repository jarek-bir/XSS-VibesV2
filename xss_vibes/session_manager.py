#!/usr/bin/env python3
"""
Session Management - Login and session management handling.

Module provides advanced HTTP session management including login,
session persistence, cookie handling and authorization.
"""

import logging
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

logger = logging.getLogger("xss_vibes.session")


@dataclass
class LoginCredentials:
    """Login credentials data."""

    username: str
    password: str
    login_url: str
    username_field: str = "username"
    password_field: str = "password"
    additional_fields: Dict[str, str] = field(default_factory=dict)
    csrf_token_name: Optional[str] = None
    csrf_selector: Optional[str] = None


@dataclass
class SessionConfig:
    """Session configuration."""

    timeout: int = 30
    max_retries: int = 3
    keep_alive: bool = True
    verify_ssl: bool = True
    user_agent: str = "XSS-Vibes/2.0"
    follow_redirects: bool = True
    cookie_jar_file: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthMethod:
    """Authentication method."""

    type: str  # 'form', 'basic', 'digest', 'bearer', 'custom'
    credentials: Optional[LoginCredentials] = None
    token: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)


class SessionManager:
    """HTTP session manager."""

    def __init__(self, config: Optional[SessionConfig] = None):
        """Initialize session manager."""
        self.config = config or SessionConfig()
        self.session = self._create_session()
        self.is_authenticated = False
        self.auth_method: Optional[AuthMethod] = None
        self.csrf_token: Optional[str] = None
        self.login_time: Optional[float] = None

    def _create_session(self) -> requests.Session:
        """Create new HTTP session."""
        session = requests.Session()

        # Configure session
        session.verify = self.config.verify_ssl
        session.headers.update(
            {"User-Agent": self.config.user_agent, **self.config.headers}
        )

        # Load cookies from file if configured
        if self.config.cookie_jar_file:
            self._load_cookies_from_file()

        return session

    def authenticate(self, auth_method: AuthMethod) -> bool:
        """Authenticate session."""
        self.auth_method = auth_method

        try:
            if auth_method.type == "form" and auth_method.credentials:
                return self._authenticate_form(auth_method.credentials)
            elif auth_method.type == "basic" and auth_method.credentials:
                return self._authenticate_basic(auth_method.credentials)
            elif auth_method.type == "digest" and auth_method.credentials:
                return self._authenticate_digest(auth_method.credentials)
            elif auth_method.type == "bearer" and auth_method.token:
                return self._authenticate_bearer(auth_method.token)
            elif auth_method.type == "custom":
                return self._authenticate_custom(auth_method.custom_headers)
            else:
                logger.error(
                    f"Unknown authentication method or missing data: {auth_method.type}"
                )
                return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

    def _authenticate_form(self, credentials: LoginCredentials) -> bool:
        """Form-based authentication."""
        if not credentials:
            logger.error("Missing login credentials")
            return False

        try:
            # Get login page
            logger.info(f"Fetching login page: {credentials.login_url}")
            response = self.session.get(credentials.login_url)
            response.raise_for_status()

            # Extract CSRF token if needed
            if credentials.csrf_token_name and credentials.csrf_selector:
                self.csrf_token = self._extract_csrf_token(
                    response.text, credentials.csrf_selector
                )
                if self.csrf_token:
                    logger.info(f"Found CSRF token: {self.csrf_token[:10]}...")

            # Prepare login data
            login_data = {
                credentials.username_field: credentials.username,
                credentials.password_field: credentials.password,
                **credentials.additional_fields,
            }

            # Add CSRF token if present
            if self.csrf_token and credentials.csrf_token_name:
                login_data[credentials.csrf_token_name] = self.csrf_token

            # Send login data
            logger.info("Sending login credentials...")
            login_response = self.session.post(
                credentials.login_url,
                data=login_data,
                allow_redirects=self.config.follow_redirects,
            )

            # Check if login was successful
            success = self._verify_login_success(login_response, credentials)

            if success:
                self.is_authenticated = True
                self.login_time = time.time()
                logger.info("Login completed successfully")

                # Save cookies
                if self.config.cookie_jar_file:
                    self._save_cookies_to_file()
            else:
                logger.warning("Login failed")

            return success

        except requests.RequestException as e:
            logger.error(f"HTTP error during login: {e}")
            return False

    def _authenticate_basic(self, credentials: LoginCredentials) -> bool:
        """HTTP Basic authentication."""
        if not credentials:
            return False

        self.session.auth = HTTPBasicAuth(credentials.username, credentials.password)

        # Test authentication
        try:
            test_url = credentials.login_url or "/"
            response = self.session.get(test_url)

            if response.status_code == 401:
                logger.error("HTTP Basic auth failed")
                return False

            self.is_authenticated = True
            self.login_time = time.time()
            logger.info("HTTP Basic auth completed successfully")
            return True

        except requests.RequestException as e:
            logger.error(f"HTTP Basic auth error: {e}")
            return False

    def _authenticate_digest(self, credentials: LoginCredentials) -> bool:
        """HTTP Digest authentication."""
        if not credentials:
            return False

        self.session.auth = HTTPDigestAuth(credentials.username, credentials.password)

        # Testuj autoryzację
        try:
            test_url = credentials.login_url or "/"
            response = self.session.get(test_url)

            if response.status_code == 401:
                logger.error("HTTP Digest auth nie powiodła się")
                return False

            self.is_authenticated = True
            self.login_time = time.time()
            logger.info("HTTP Digest auth zakończona sukcesem")
            return True

        except requests.RequestException as e:
            logger.error(f"Błąd HTTP Digest auth: {e}")
            return False

    def _authenticate_bearer(self, token: str) -> bool:
        """Autoryzacja Bearer token."""
        if not token:
            logger.error("Brak Bearer token")
            return False

        self.session.headers.update({"Authorization": f"Bearer {token}"})

        self.is_authenticated = True
        self.login_time = time.time()
        logger.info("Bearer token auth ustawiona")
        return True

    def _authenticate_custom(self, custom_headers: Dict[str, str]) -> bool:
        """Autoryzacja custom headers."""
        if not custom_headers:
            logger.error("Brak custom headers")
            return False

        self.session.headers.update(custom_headers)

        self.is_authenticated = True
        self.login_time = time.time()
        logger.info("Custom headers auth ustawiona")
        return True

    def _extract_csrf_token(self, html_content: str, selector: str) -> Optional[str]:
        """Wyodrębnia CSRF token z HTML."""
        import re

        # Różne wzorce dla CSRF tokenów
        patterns = [
            rf'<input[^>]+name=["\']?{re.escape(selector)}["\']?[^>]+value=["\']([^"\']+)["\']',
            rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(selector)}["\']?',
            rf'<meta[^>]+name=["\']?{re.escape(selector)}["\']?[^>]+content=["\']([^"\']+)["\']',
            rf'["\']?{re.escape(selector)}["\']?\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)

        logger.warning(f"Nie znaleziono CSRF token dla selektora: {selector}")
        return None

    def _verify_login_success(
        self, response: requests.Response, credentials: LoginCredentials
    ) -> bool:
        """Weryfikuje czy logowanie się powiodło."""
        # Sprawdź status code
        if response.status_code >= 400:
            return False

        # Sprawdź czy nie ma przekierowania na stronę logowania
        if credentials.login_url in response.url:
            return False

        # Sprawdź czy nie ma błędów w treści
        error_indicators = [
            "invalid",
            "incorrect",
            "wrong",
            "error",
            "failed",
            "błąd",
            "nieprawidłowy",
            "niepoprawny",
        ]

        response_text = response.text.lower()
        if any(indicator in response_text for indicator in error_indicators):
            return False

        # Sprawdź czy są wskaźniki sukcesu
        success_indicators = [
            "dashboard",
            "welcome",
            "logout",
            "profile",
            "settings",
            "panel",
            "witamy",
            "wyloguj",
        ]

        if any(indicator in response_text for indicator in success_indicators):
            return True

        # Domyślnie uznaj za sukces jeśli nie ma błędów
        return True

    def refresh_session(self) -> bool:
        """Odświeża sesję jeśli to konieczne."""
        if not self.is_authenticated or not self.auth_method:
            return False

        # Sprawdź czy sesja nie wygasła (przykład: 1 godzina)
        if self.login_time and time.time() - self.login_time > 3600:
            logger.info("Sesja mogła wygasnąć, ponawiam autoryzację...")
            return self.authenticate(self.auth_method)

        return True

    def make_authenticated_request(
        self, method: str, url: str, **kwargs
    ) -> requests.Response:
        """Wykonuje uwierzytelnione żądanie HTTP."""
        # Odśwież sesję jeśli potrzeba
        self.refresh_session()

        # Wykonaj żądanie
        response = self.session.request(method, url, **kwargs)

        # Jeśli unauthorized, spróbuj ponownie zalogować
        if response.status_code == 401 and self.auth_method:
            logger.info("Otrzymano 401, ponawiam autoryzację...")
            if self.authenticate(self.auth_method):
                response = self.session.request(method, url, **kwargs)

        return response

    def get_session_info(self) -> Dict[str, Any]:
        """Zwraca informacje o sesji."""
        cookies_count = len(self.session.cookies)

        return {
            "authenticated": self.is_authenticated,
            "auth_method": self.auth_method.type if self.auth_method else None,
            "login_time": self.login_time,
            "session_age": time.time() - self.login_time if self.login_time else None,
            "cookies_count": cookies_count,
            "user_agent": self.session.headers.get("User-Agent"),
            "csrf_token": bool(self.csrf_token),
            "verify_ssl": self.session.verify,
        }

    def _load_cookies_from_file(self):
        """Ładuje cookies z pliku."""
        cookie_file = Path(self.config.cookie_jar_file)
        if cookie_file.exists():
            try:
                with open(cookie_file, "r") as f:
                    cookies_data = json.load(f)

                for cookie_data in cookies_data:
                    self.session.cookies.set(**cookie_data)

                logger.info(f"Załadowano {len(cookies_data)} cookies z pliku")

            except Exception as e:
                logger.error(f"Błąd ładowania cookies: {e}")

    def _save_cookies_to_file(self):
        """Zapisuje cookies do pliku."""
        if not self.config.cookie_jar_file:
            return

        try:
            cookies_data = []
            for cookie in self.session.cookies:
                cookie_dict = {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "rest": getattr(cookie, "rest", {}),
                }
                cookies_data.append(cookie_dict)

            cookie_file = Path(self.config.cookie_jar_file)
            cookie_file.parent.mkdir(parents=True, exist_ok=True)

            with open(cookie_file, "w") as f:
                json.dump(cookies_data, f, indent=2)

            logger.info(f"Zapisano {len(cookies_data)} cookies do pliku")

        except Exception as e:
            logger.error(f"Błąd zapisywania cookies: {e}")

    def logout(self, logout_url: Optional[str] = None):
        """Wylogowuje z sesji."""
        if logout_url and self.is_authenticated:
            try:
                self.session.get(logout_url)
                logger.info("Wylogowano z sesji")
            except Exception as e:
                logger.error(f"Błąd wylogowania: {e}")

        self.is_authenticated = False
        self.auth_method = None
        self.csrf_token = None
        self.login_time = None

        # Wyczyść cookies
        self.session.cookies.clear()

        # Usuń headers autoryzacji
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]

    def close(self):
        """Zamyka sesję."""
        if self.config.cookie_jar_file and self.is_authenticated:
            self._save_cookies_to_file()

        self.session.close()
        logger.info("Sesja zamknięta")


class SessionProfileManager:
    """Manager profili sesji."""

    def __init__(self, profiles_file: str = "session_profiles.json"):
        """Inicjalizacja managera profili."""
        self.profiles_file = Path(profiles_file)
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.load_profiles()

    def load_profiles(self):
        """Ładuje profile z pliku."""
        if self.profiles_file.exists():
            try:
                with open(self.profiles_file, "r") as f:
                    self.profiles = json.load(f)
                logger.info(f"Załadowano {len(self.profiles)} profili sesji")
            except Exception as e:
                logger.error(f"Błąd ładowania profili: {e}")
                self.profiles = {}

    def save_profiles(self):
        """Zapisuje profile do pliku."""
        try:
            self.profiles_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.profiles_file, "w") as f:
                json.dump(self.profiles, f, indent=2)
            logger.info("Profile sesji zapisane")
        except Exception as e:
            logger.error(f"Błąd zapisywania profili: {e}")

    def add_profile(
        self,
        name: str,
        credentials: LoginCredentials,
        config: Optional[SessionConfig] = None,
    ):
        """Dodaje nowy profil sesji."""
        profile_data = {
            "credentials": {
                "username": credentials.username,
                "password": credentials.password,  # W produkcji należy zaszyfrować!
                "login_url": credentials.login_url,
                "username_field": credentials.username_field,
                "password_field": credentials.password_field,
                "additional_fields": credentials.additional_fields,
                "csrf_token_name": credentials.csrf_token_name,
                "csrf_selector": credentials.csrf_selector,
            }
        }

        if config:
            profile_data["config"] = {
                "timeout": config.timeout,
                "max_retries": config.max_retries,
                "keep_alive": config.keep_alive,
                "verify_ssl": config.verify_ssl,
                "user_agent": config.user_agent,
                "follow_redirects": config.follow_redirects,
                "headers": config.headers,
            }

        self.profiles[name] = profile_data
        self.save_profiles()
        logger.info(f"Dodano profil sesji: {name}")

    def get_profile(
        self, name: str
    ) -> Optional[Tuple[LoginCredentials, SessionConfig]]:
        """Pobiera profil sesji."""
        if name not in self.profiles:
            logger.error(f"Profil {name} nie istnieje")
            return None

        profile_data = self.profiles[name]

        # Odtwórz credentials
        cred_data = profile_data["credentials"]
        credentials = LoginCredentials(
            username=cred_data["username"],
            password=cred_data["password"],
            login_url=cred_data["login_url"],
            username_field=cred_data.get("username_field", "username"),
            password_field=cred_data.get("password_field", "password"),
            additional_fields=cred_data.get("additional_fields", {}),
            csrf_token_name=cred_data.get("csrf_token_name"),
            csrf_selector=cred_data.get("csrf_selector"),
        )

        # Odtwórz config
        config_data = profile_data.get("config", {})
        config = SessionConfig(
            timeout=config_data.get("timeout", 30),
            max_retries=config_data.get("max_retries", 3),
            keep_alive=config_data.get("keep_alive", True),
            verify_ssl=config_data.get("verify_ssl", True),
            user_agent=config_data.get("user_agent", "XSS-Vibes/2.0"),
            follow_redirects=config_data.get("follow_redirects", True),
            headers=config_data.get("headers", {}),
        )

        return credentials, config

    def list_profiles(self) -> List[str]:
        """Zwraca listę dostępnych profili."""
        return list(self.profiles.keys())

    def remove_profile(self, name: str) -> bool:
        """Usuwa profil sesji."""
        if name in self.profiles:
            del self.profiles[name]
            self.save_profiles()
            logger.info(f"Usunięto profil sesji: {name}")
            return True
        return False
