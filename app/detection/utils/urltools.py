"""
Safe URL parsing and decoding utilities for attack detection.
All functions implement strict bounds to prevent DoS.
"""
import urllib.parse
import logging

logger = logging.getLogger(__name__)

# Safety constants
MAX_URL_LEN = 8192
MAX_DECODE_LEN = 4096
MAX_NORMALIZE_LEN = 2048


def split_url(url: str) -> tuple[str, str]:
    """
    Split URL into path and query components.
    
    Args:
        url: Full URL string (may include query)
    
    Returns:
        Tuple of (path, query_string)
    
    Security:
        - Bounds input to MAX_URL_LEN
        - Returns empty strings if parsing fails
    """
    if not url:
        return "", ""
    
    # Security: Cap input length
    url = url[:MAX_URL_LEN]
    
    try:
        if '?' in url:
            parts = url.split('?', 1)
            return parts[0], parts[1]
        else:
            return url, ""
    except Exception as e:
        logger.warning(f"Error splitting URL: {e}")
        return "", ""


def safe_unquote(value: str, max_len: int = MAX_DECODE_LEN) -> str:
    """
    Safely URL-decode a string with strict validation.
    
    Args:
        value: URL-encoded string
        max_len: Maximum allowed length for input and output
    
    Returns:
        Decoded string (capped to max_len)
    
    Security:
        - Rejects null bytes, CR, LF in output
        - Caps input and output length
        - Returns empty string on error (fail-safe)
    
    Raises:
        ValueError: If decoded output contains CRLF or null bytes
    """
    if not value:
        return ""
    
    # Security: Cap input length
    value = value[:max_len]
    
    try:
        # Decode using urllib (safe, no code execution)
        decoded = urllib.parse.unquote(value)
        
        # Security: Cap output length
        decoded = decoded[:max_len]
        
        # Security: Reject dangerous characters in decoded output
        if '\x00' in decoded:
            raise ValueError("Decoded value contains null byte")
        if '\r' in decoded or '\n' in decoded:
            raise ValueError("Decoded value contains CR or LF")
        
        return decoded
    
    except ValueError:
        # Re-raise validation errors
        raise
    except Exception as e:
        logger.warning(f"Error decoding URL: {e}")
        return ""


def normalize_for_matching(s: str, max_len: int = MAX_NORMALIZE_LEN) -> str:
    """
    Normalize string for pattern matching.
    
    Normalization:
        - Convert to lowercase
        - Collapse multiple whitespace to single space
        - Strip leading/trailing whitespace
        - Truncate to max_len
    
    Args:
        s: String to normalize
        max_len: Maximum output length
    
    Returns:
        Normalized string
    
    Security:
        - Bounds output length
        - Never throws (fail-safe)
    """
    if not s:
        return ""
    
    try:
        # Cap input
        s = s[:max_len * 2]  # Allow some headroom before normalization
        
        # Lowercase
        s = s.lower()
        
        # Collapse whitespace
        s = ' '.join(s.split())
        
        # Cap output
        s = s[:max_len]
        
        return s
    except Exception as e:
        logger.warning(f"Error normalizing string: {e}")
        return ""


def extract_query_params(query_string: str) -> dict[str, list[str]]:
    """
    Parse query string into parameter dictionary.
    
    Args:
        query_string: URL query string (without '?')
    
    Returns:
        Dict mapping parameter names to list of values
    
    Security:
        - Caps input length
        - Returns empty dict on error (fail-safe)
    """
    if not query_string:
        return {}
    
    # Security: Cap input
    query_string = query_string[:MAX_DECODE_LEN]
    
    try:
        # Use urllib's safe parser
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        return parsed
    except Exception as e:
        logger.warning(f"Error parsing query params: {e}")
        return {}
