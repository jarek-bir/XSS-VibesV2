"""Data models for XSS Vibes scanner."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from urllib.parse import ParseResult


class VulnerabilityLevel(Enum):
    """Severity levels for vulnerabilities."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(Enum):
    """Status of a scan."""

    PENDING = "pending"
    SCANNING = "scanning"
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    ERROR = "error"


class PayloadType(Enum):
    """Types of XSS payloads."""

    BASIC = "basic"
    SCRIPT = "script"
    EVENT = "event"
    ATTRIBUTE = "attribute"
    ENCODED = "encoded"
    FILTER_BYPASS = "filter_bypass"


@dataclass
class Payload:
    """Represents an XSS payload."""

    content: str
    attributes: List[str] = field(default_factory=list)
    waf: Optional[str] = None
    count: int = 0
    description: Optional[str] = None
    level: VulnerabilityLevel = VulnerabilityLevel.MEDIUM
    context: Optional[str] = (
        None  # Injection context (html_attribute, javascript_string, etc.)
    )
    bypass_potential: int = 5  # 1-10 scale for WAF bypass potential

    def __post_init__(self):
        """Extract dangerous characters from payload."""
        dangerous_chars = [">", "'", '"', "<", "/", ";", "(", ")", "{", "}", "[", "]"]
        self.attributes = list(
            set(char for char in self.content if char in dangerous_chars)
        )


@dataclass
class ScanTarget:
    """Represents a scan target URL with parameters."""

    url: str
    parsed_url: Optional[ParseResult] = None
    parameters: List[str] = field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING

    def __post_init__(self):
        from urllib.parse import urlparse, parse_qs

        self.parsed_url = urlparse(self.url)
        if self.parsed_url.query:
            query_params = parse_qs(self.parsed_url.query)
            self.parameters = list(query_params.keys())


@dataclass
class VulnerabilityResult:
    """Represents a found vulnerability."""

    url: str
    parameter: str
    payload: str
    response_snippet: Optional[str] = None
    level: VulnerabilityLevel = VulnerabilityLevel.MEDIUM
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            from datetime import datetime

            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "response_snippet": self.response_snippet,
            "level": self.level.value,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    """Represents the complete scan result."""

    target: ScanTarget
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_duration: Optional[float] = None
    waf_detected: Optional[str] = None

    @property
    def is_vulnerable(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0

    @property
    def highest_severity(self) -> Optional[VulnerabilityLevel]:
        """Get the highest severity level found."""
        if not self.vulnerabilities:
            return None

        severity_order = [
            VulnerabilityLevel.CRITICAL,
            VulnerabilityLevel.HIGH,
            VulnerabilityLevel.MEDIUM,
            VulnerabilityLevel.LOW,
        ]

        for level in severity_order:
            if any(vuln.level == level for vuln in self.vulnerabilities):
                return level

        return VulnerabilityLevel.LOW

    # Compatibility properties for reporting
    @property
    def url(self) -> str:
        """Get URL for compatibility."""
        return self.target.url

    @property
    def status(self) -> ScanStatus:
        """Get status for compatibility."""
        return ScanStatus.VULNERABLE if self.is_vulnerable else ScanStatus.SAFE

    @property
    def vulnerability_level(self) -> Optional[VulnerabilityLevel]:
        """Get vulnerability level for compatibility."""
        return self.highest_severity

    @property
    def payload(self) -> str:
        """Get first payload for compatibility."""
        if self.vulnerabilities:
            return self.vulnerabilities[0].payload
        return ""

    @property
    def parameter(self) -> str:
        """Get first parameter for compatibility."""
        if self.vulnerabilities:
            return self.vulnerabilities[0].parameter
        return ""

    @property
    def response_time(self) -> float:
        """Get response time for compatibility."""
        return self.scan_duration or 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target": {
                "url": self.target.url,
                "parameters": self.target.parameters,
                "status": self.target.status.value,
            },
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
            "errors": self.errors,
            "scan_duration": self.scan_duration,
            "waf_detected": self.waf_detected,
            "is_vulnerable": self.is_vulnerable,
            "highest_severity": (
                self.highest_severity.value if self.highest_severity else None
            ),
        }
