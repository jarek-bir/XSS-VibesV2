"""Logging configuration for XSS Vibes scanner."""

import logging
import sys
from pathlib import Path
from typing import Optional
from colorama import Fore, Style


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.WHITE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA,
        'SUCCESS': Fore.GREEN,
        'VULNERABLE': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logging(
    level: str = "INFO", 
    log_file: Optional[Path] = None,
    enable_colors: bool = True
) -> logging.Logger:
    """Setup logging configuration."""
    
    logger = logging.getLogger("xss_vibes")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    
    if enable_colors:
        console_format = "%(levelname)s - %(message)s"
        console_formatter = ColoredFormatter(console_format)
    else:
        console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        console_formatter = logging.Formatter(console_format)
    
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        file_formatter = logging.Formatter(file_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


# Add custom log levels
logging.addLevelName(25, 'SUCCESS')
logging.addLevelName(35, 'VULNERABLE')


def success(self, message, *args, **kwargs):
    if self.isEnabledFor(25):
        self._log(25, message, args, **kwargs)


def vulnerable(self, message, *args, **kwargs):
    if self.isEnabledFor(35):
        self._log(35, message, args, **kwargs)


# Add custom methods to logger
logging.Logger.success = success
logging.Logger.vulnerable = vulnerable
