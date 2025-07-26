"""Modern URL utilities and crawling functionality."""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import urlparse, urljoin
import re

from config import ScannerConfig


logger = logging.getLogger("xss_vibes.url_utils")


class URLCrawler:
    """Modern URL crawler using katana."""
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """
        Initialize URL crawler.
        
        Args:
            config: Scanner configuration
        """
        self.config = config or ScannerConfig()
    
    def crawl_url(
        self, 
        url: str, 
        depth: Optional[int] = None, 
        output_file: Optional[Path] = None
    ) -> List[str]:
        """
        Crawl URLs using katana.
        
        Args:
            url: Target URL to crawl
            depth: Crawling depth
            output_file: Output file path
            
        Returns:
            List of discovered URLs
        """
        depth = depth or self.config.crawl_depth
        
        if not output_file:
            parsed = urlparse(url)
            hostname = parsed.hostname or "unknown"
            output_file = Path(f"{hostname}_katana.txt")
        
        logger.info(f"Crawling {url} with depth {depth}")
        
        try:
            # Build katana command
            cmd = [
                "katana",
                "-u", url,
                "-jc",  # JavaScript crawling
                "-d", str(depth),
                "-o", str(output_file)
            ]
            
            # Run katana
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Katana failed: {result.stderr}")
                return []
            
            logger.info(f"Crawling completed, results saved to {output_file}")
            
            # Read and return URLs
            if output_file.exists():
                return self.read_urls_from_file(output_file)
            else:
                logger.warning("Crawl output file not found")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error("Katana crawling timed out")
            return []
        except FileNotFoundError:
            logger.error("Katana not found. Please install katana for crawling functionality")
            return []
        except Exception as e:
            logger.error(f"Error during crawling: {e}")
            return []
    
    def read_urls_from_file(self, file_path: Path) -> List[str]:
        """
        Read URLs from file and filter for GET parameters.
        
        Args:
            file_path: Path to file containing URLs
            
        Returns:
            List of URLs with GET parameters
        """
        if not file_path.exists():
            logger.error(f"URL file {file_path} not found")
            return []
        
        try:
            logger.info(f"Reading URLs from {file_path}")
            
            # Use subprocess to filter URLs with parameters
            result = subprocess.run(
                ["grep", "=", str(file_path)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning("No URLs with GET parameters found")
                return []
            
            urls = result.stdout.strip().split('\n')
            
            # Remove duplicates while preserving order
            unique_urls = []
            seen = set()
            
            for url in urls:
                url = url.strip()
                if url and url not in seen:
                    unique_urls.append(url)
                    seen.add(url)
            
            logger.info(f"Found {len(unique_urls)} unique URLs with parameters")
            return unique_urls
            
        except Exception as e:
            logger.error(f"Error reading URLs from file: {e}")
            return []
    
    def filter_urls_with_parameters(self, urls: List[str]) -> List[str]:
        """
        Filter URLs to only include those with GET parameters.
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of URLs containing GET parameters
        """
        filtered_urls = []
        
        for url in urls:
            parsed = urlparse(url)
            if parsed.query and '=' in parsed.query:
                filtered_urls.append(url)
        
        return filtered_urls
    
    def validate_url(self, url: str) -> bool:
        """
        Validate if URL is properly formatted.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL format.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        
        # Remove default ports
        netloc = parsed.netloc
        if ':80' in netloc and parsed.scheme == 'http':
            netloc = netloc.replace(':80', '')
        elif ':443' in netloc and parsed.scheme == 'https':
            netloc = netloc.replace(':443', '')
        
        return f"{parsed.scheme}://{netloc}{parsed.path}"


class URLProcessor:
    """Utility class for URL processing operations."""
    
    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return None
    
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        domain1 = URLProcessor.extract_domain(url1)
        domain2 = URLProcessor.extract_domain(url2)
        return domain1 == domain2 if domain1 and domain2 else False
    
    @staticmethod
    def get_base_url(url: str) -> str:
        """Get base URL without query parameters."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    @staticmethod
    def replace_parameter_value(url: str, param_name: str, new_value: str) -> str:
        """
        Replace parameter value in URL.
        
        Args:
            url: Original URL
            param_name: Parameter name to replace
            new_value: New parameter value
            
        Returns:
            URL with replaced parameter value
        """
        pattern = f"{re.escape(param_name)}=([^&]*)"
        replacement = f"{param_name}={new_value}"
        return re.sub(pattern, replacement, url)
    
    @staticmethod
    def get_parameter_names(url: str) -> List[str]:
        """
        Extract parameter names from URL.
        
        Args:
            url: URL to extract parameters from
            
        Returns:
            List of parameter names
        """
        parsed = urlparse(url)
        if not parsed.query:
            return []
        
        param_names = []
        for param_pair in parsed.query.split('&'):
            if '=' in param_pair:
                param_name = param_pair.split('=')[0]
                param_names.append(param_name)
        
        return param_names


class FileURLReader:
    """Read URLs from various file formats."""
    
    @staticmethod
    def read_from_stdin() -> List[str]:
        """Read URLs from standard input."""
        import sys
        
        urls = []
        try:
            for line in sys.stdin:
                url = line.strip()
                if url:
                    urls.append(url)
        except KeyboardInterrupt:
            logger.info("Reading from stdin interrupted")
        
        return urls
    
    @staticmethod
    def read_from_file(file_path: Path) -> List[str]:
        """
        Read URLs from a text file.
        
        Args:
            file_path: Path to file containing URLs
            
        Returns:
            List of URLs
        """
        if not file_path.exists():
            logger.error(f"File {file_path} not found")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Read {len(urls)} URLs from {file_path}")
            return urls
            
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return []
