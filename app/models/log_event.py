"""
Pydantic models for Nginx access log events.
Implements strict validation and normalization for security.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress, ConfigDict
from enum import Enum


class HTTPMethod(str, Enum):
    """Valid HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    TRACE = "TRACE"


class LogEvent(BaseModel):
    """
    Normalized Nginx access log event model.
    
    Security considerations:
    - All fields are validated and sanitized
    - IP addresses are validated using pydantic's IPvAnyAddress
    - HTTP methods are restricted to valid enum values
    - Strings are not executed or eval'd
    - Timestamps are parsed safely
    - Model is immutable after creation (frozen=True)
    - CRLF and null bytes are rejected
    """
    
    # Pydantic v2 configuration
    model_config = ConfigDict(
        frozen=True,  # Immutable after creation
        use_enum_values=True  # Use enum values directly
    )
    
    # Request metadata
    timestamp: datetime = Field(..., description="Request timestamp in ISO8601 format")
    remote_ip: str = Field(..., description="Client IP address", max_length=45)
    
    # HTTP request details
    method: HTTPMethod = Field(..., description="HTTP method")
    url: str = Field(..., description="Request URL path and query string", max_length=8192)
    status: Optional[int] = Field(None, description="HTTP status code", ge=100, le=599)
    
    # Headers and metadata
    user_agent: Optional[str] = Field(None, description="User-Agent header", max_length=1024)
    referer: Optional[str] = Field(None, description="Referer header", max_length=2048)
    
    # Response metrics
    body_bytes_sent: int = Field(0, description="Response body size in bytes", ge=0)
    request_time: float = Field(0.0, description="Request processing time in seconds", ge=0)
    
    @field_validator('remote_ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format (IPv4 or IPv6)"""
        try:
            # Pydantic will validate the IP format
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid IP address format: {v}")
    
    @field_validator('url')
    @classmethod
    def sanitize_url(cls, v: str) -> str:
        """
        Sanitize URL - reject dangerous characters.
        
        Security: Reject null bytes, CR, LF to prevent log injection and CRLF attacks.
        """
        # Reject null bytes (log injection)
        if '\x00' in v:
            raise ValueError("URL contains null byte")
        
        # Reject CRLF (log injection, HTTP response splitting)
        if '\r' in v or '\n' in v:
            raise ValueError("URL contains CR or LF character")
        
        # Remove other ASCII control characters (< 0x20 and 0x7f)
        sanitized = ''.join(char for char in v if ord(char) >= 0x20 and ord(char) != 0x7f)
        
        return sanitized.strip()
    
    @field_validator('user_agent', 'referer')
    @classmethod
    def sanitize_header(cls, v: Optional[str]) -> Optional[str]:
        """
        Sanitize header values - reject dangerous characters.
        
        Security: Reject null bytes, CR, LF to prevent log injection attacks.
        """
        if v is None:
            return None
        
        # Reject null bytes (log injection)
        if '\x00' in v:
            raise ValueError("Header contains null byte")
        
        # Reject CRLF (log injection, header injection)
        if '\r' in v or '\n' in v:
            raise ValueError("Header contains CR or LF character")
        
        # Remove other ASCII control characters (< 0x20 and 0x7f)
        sanitized = ''.join(char for char in v if ord(char) >= 0x20 and ord(char) != 0x7f)
        
        return sanitized.strip() if sanitized else None

