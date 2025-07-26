"""XSS Vibes - Modern XSS Scanner Package."""

__version__ = "2.0.0"
__author__ = "Faiyaz Ahmad"
__description__ = "Modern XSS Scanner with WAF evasion capabilities"
__url__ = "https://github.com/faiyazahmad07/xss_vibes"

# Main exports
from .scanner import XSSScanner
from .payload_manager import PayloadManager
from .waf_detector import WAFDetector
from .models import ScanResult, VulnerabilityResult, VulnerabilityLevel
from .config import ScannerConfig

__all__ = [
    "__version__",
    "__author__",
    "__description__",
    "__url__",
    "XSSScanner",
    "PayloadManager",
    "WAFDetector",
    "ScanResult",
    "VulnerabilityResult",
    "VulnerabilityLevel",
    "ScannerConfig",
]
