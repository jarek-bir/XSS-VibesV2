"""Modern header parser module."""

import re
from typing import Dict, List, Optional


class HeaderParser:
    """Parser for HTTP headers."""
    
    @staticmethod
    def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
        """
        Parse header strings into a dictionary.
        
        Args:
            header_list: List of header strings in format "key: value"
            
        Returns:
            Dictionary of parsed headers
        """
        if not header_list:
            return {}
        
        headers = {}
        for header_str in header_list:
            if not header_str or ':' not in header_str:
                continue
                
            key_value = re.split(r':\s*', header_str.strip(), 1)
            if len(key_value) == 2:
                key, value = key_value
                headers[key.strip()] = value.strip()
        
        return headers
    
    @staticmethod
    def parse_header_string(header_string: str, delimiter: str = ',') -> Dict[str, str]:
        """
        Parse a comma-separated string of headers.
        
        Args:
            header_string: String containing headers separated by delimiter
            delimiter: Character used to separate headers
            
        Returns:
            Dictionary of parsed headers
        """
        if not header_string:
            return {}
        
        header_list = header_string.split(delimiter)
        return HeaderParser.parse_headers(header_list)
    
    @staticmethod
    def validate_headers(headers: Dict[str, str]) -> bool:
        """
        Validate that headers are properly formatted.
        
        Args:
            headers: Dictionary of headers to validate
            
        Returns:
            True if headers are valid, False otherwise
        """
        if not isinstance(headers, dict):
            return False
        
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                return False
            if not key.strip() or '\n' in key or '\r' in key:
                return False
            if '\n' in value or '\r' in value:
                return False
        
        return True


# Backward compatibility alias
class Parser:
    """Legacy parser class for backward compatibility."""
    
    @staticmethod
    def headerParser(input_list: List[str]) -> Dict[str, str]:
        """Legacy method name for backward compatibility."""
        return HeaderParser.parse_headers(input_list)
