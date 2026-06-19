"""
Builtin detection rules for common web attack patterns.
12 conservative, low-false-positive rules with safe regex and bounds.
"""
import re
import logging
from typing import Optional
from app.models import LogEvent
from .base import BaseRule
from .models import RuleMatch, Severity

logger = logging.getLogger(__name__)

# Safe regex patterns with bounds
# Only used after length checks to prevent ReDoS
UNION_SELECT_PATTERN = re.compile(
    r'\b(union\s+(all\s+)?select)\b',
    re.IGNORECASE | re.DOTALL
)


class SQLiUnionSelectRule(BaseRule):
    """Detect SQL injection UNION SELECT patterns"""
    
    def get_rule_id(self) -> str:
        return "sqli_union_select"
    
    def get_name(self) -> str:
        return "SQL Injection - UNION SELECT"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["sqli", "injection", "database", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """
        Check for UNION SELECT patterns in decoded query.
        
        Security: Only applies regex after length cap (max 4096)
        """
        try:
            decoded_query = derived.get("decoded_query", "")
            
            # Security: Skip if query too long (prevent ReDoS)
            if len(decoded_query) > 4096:
                return None
            
            # Check for UNION SELECT pattern
            if UNION_SELECT_PATTERN.search(decoded_query):
                # Extract evidence snippet
                match = UNION_SELECT_PATTERN.search(decoded_query)
                start = max(0, match.start() - 20)
                end = min(len(decoded_query), match.end() + 20)
                evidence = decoded_query[start:end]
                
                return self._create_match(
                    confidence=0.90,
                    evidence=f"UNION SELECT pattern: {evidence}",
                    fields_used=["url", "query"]
                )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class SQLiTautologyRule(BaseRule):
    """Detect SQL tautology patterns (e.g., ' OR '1'='1)"""
    
    # Tautology patterns (substring checks, no regex needed)
    TAUTOLOGY_PATTERNS = [
        "' or 1=1",
        '" or 1=1',
        "' or '1'='1",
        '" or "1"="1',
        "' or 'a'='a",
        '" or "a"="a',
        "or 1=1--",
        "or 1=1#",
    ]
    
    def get_rule_id(self) -> str:
        return "sqli_tautology"
    
    def get_name(self) -> str:
        return "SQL Injection - Tautology"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["sqli", "injection", "auth-bypass", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for SQL tautology patterns"""
        try:
            decoded_query = derived.get("decoded_query", "").lower()
            normalized_query = derived.get("normalized_query", "")
            
            # Check each tautology pattern
            for pattern in self.TAUTOLOGY_PATTERNS:
                if pattern in decoded_query or pattern in normalized_query:
                    # Find position for evidence
                    pos = decoded_query.find(pattern)
                    if pos == -1:
                        pos = normalized_query.find(pattern)
                        source = normalized_query
                    else:
                        source = decoded_query
                    
                    start = max(0, pos - 10)
                    end = min(len(source), pos + len(pattern) + 10)
                    evidence = source[start:end]
                    
                    return self._create_match(
                        confidence=0.85,
                        evidence=f"Tautology: {evidence}",
                        fields_used=["url", "query"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class SQLiTimeBasedRule(BaseRule):
    """Detect time-based SQL injection patterns"""
    
    TIME_BASED_PATTERNS = [
        "sleep(",
        "benchmark(",
        "waitfor delay",
        "pg_sleep(",
        "dbms_lock.sleep",
    ]
    
    def get_rule_id(self) -> str:
        return "sqli_time_based"
    
    def get_name(self) -> str:
        return "SQL Injection - Time-Based"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["sqli", "injection", "blind-sqli", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for time-based blind SQLi patterns"""
        try:
            decoded_query = derived.get("decoded_query", "").lower()
            
            for pattern in self.TIME_BASED_PATTERNS:
                if pattern in decoded_query:
                    pos = decoded_query.find(pattern)
                    start = max(0, pos - 15)
                    end = min(len(decoded_query), pos + len(pattern) + 15)
                    evidence = decoded_query[start:end]
                    
                    return self._create_match(
                        confidence=0.80,
                        evidence=f"Time-based pattern: {evidence}",
                        fields_used=["url", "query"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class XSSScriptTagRawRule(BaseRule):
    """Detect raw <script> tags in URLs"""
    
    def get_rule_id(self) -> str:
        return"xss_script_tag_raw"
    
    def get_name(self) -> str:
        return "XSS - Script Tag (Raw)"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["xss", "injection", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for <script> in decoded URL or query"""
        try:
            decoded_url = derived.get("decoded_url", "").lower()
            decoded_query = derived.get("decoded_query", "").lower()
            
            for source, field in [(decoded_url, "url"), (decoded_query, "query")]:
                if "<script" in source:
                    pos = source.find("<script")
                    start = max(0, pos - 10)
                    end = min(len(source), pos + 20)
                    evidence = source[start:end]
                    
                    return self._create_match(
                        confidence=0.90,
                        evidence=f"Script tag: {evidence}",
                        fields_used=["url", field]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class XSSScriptTagEncodedRule(BaseRule):
    """Detect URL-encoded <script> tags"""
    
    def get_rule_id(self) -> str:
        return "xss_script_tag_encoded"
    
    def get_name(self) -> str:
        return "XSS - Script Tag (Encoded)"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_tags(self) -> list[str]:
        return ["xss", "injection", "encoded", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for %3cscript in raw URL (encoded <script>)"""
        try:
            url_lower = event.url.lower()
            
            if "%3cscript" in url_lower:
                pos = url_lower.find("%3cscript")
                start = max(0, pos - 10)
                end = min(len(url_lower), pos + 25)
                evidence = event.url[start:end]
                
                return self._create_match(
                    confidence=0.85,
                    evidence=f"Encoded script: {evidence}",
                    fields_used=["url"]
                )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class XSSEventHandlersRule(BaseRule):
    """Detect XSS event handler attributes"""
    
    EVENT_HANDLERS = [
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onblur=",
    ]
    
    def get_rule_id(self) -> str:
        return "xss_event_handlers"
    
    def get_name(self) -> str:
        return "XSS - Event Handlers"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_tags(self) -> list[str]:
        return ["xss", "injection", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for JavaScript event handlers in query"""
        try:
            decoded_query = derived.get("decoded_query", "").lower()
            
            for handler in self.EVENT_HANDLERS:
                if handler in decoded_query:
                    pos = decoded_query.find(handler)
                    start = max(0, pos - 10)
                    end = min(len(decoded_query), pos + len(handler) + 15)
                    evidence = decoded_query[start:end]
                    
                    return self._create_match(
                        confidence=0.75,
                        evidence=f"Event handler: {evidence}",
                        fields_used=["url", "query"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class TraversalRawRule(BaseRule):
    """Detect raw path traversal patterns"""
    
    def get_rule_id(self) -> str:
        return "traversal_raw"
    
    def get_name(self) -> str:
        return "Path Traversal - Raw"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["traversal", "lfi", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for ../ in path or query"""
        try:
            path = derived.get("path", "")
            decoded_query = derived.get("decoded_query", "")
            
            for source, field in [(path, "path"), (decoded_query, "query")]:
                if "../" in source or "..\\" in source:
                    pattern = "../" if "../" in source else "..\\"
                    pos = source.find(pattern)
                    start = max(0, pos - 10)
                    end = min(len(source), pos + 20)
                    evidence = source[start:end]
                    
                    return self._create_match(
                        confidence=0.85,
                        evidence=f"Traversal: {evidence}",
                        fields_used=["url", field]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class TraversalEncodedRule(BaseRule):
    """Detect URL-encoded path traversal"""
    
    def get_rule_id(self) -> str:
        return "traversal_encoded"
    
    def get_name(self) -> str:
        return "Path Traversal - Encoded"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_tags(self) -> list[str]:
        return ["traversal", "lfi", "encoded", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for %2e%2e%2f (encoded ../) in raw URL"""
        try:
            url_lower = event.url.lower()
            
            # Check for various encodings of ../
            encoded_patterns = ["%2e%2e%2f", "%2e%2e/", "..%2f"]
            
            for pattern in encoded_patterns:
                if pattern in url_lower:
                    pos = url_lower.find(pattern)
                    start = max(0, pos - 10)
                    end = min(len(url_lower), pos + 25)
                    evidence = event.url[start:end]
                    
                    return self._create_match(
                        confidence=0.80,
                        evidence=f"Encoded traversal: {evidence}",
                        fields_used=["url"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class SensitiveFileProbeRule(BaseRule):
    """Detect probes for sensitive files"""
    
    SENSITIVE_PATHS = [
        "/.env",
        "/wp-config.php",
        "/phpmyadmin",
        "/.git",
        "/server-status",
        "/.aws/credentials",
        "/config.php",
        "/database.yml",
        "/.htaccess",
    ]
    
    def get_rule_id(self) -> str:
        return "sensitive_file_probe"
    
    def get_name(self) -> str:
        return "Sensitive File Probe"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_tags(self) -> list[str]:
        return ["reconnaissance", "probe", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for sensitive file access attempts"""
        try:
            path = derived.get("path", "").lower()
            
            for sensitive in self.SENSITIVE_PATHS:
                if sensitive in path:
                    return self._create_match(
                        confidence=0.70,
                        evidence=f"Sensitive file: {path[:80]}",
                        fields_used=["url", "path"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class CmdInjectionRule(BaseRule):
    """Detect command injection patterns"""
    
    CMD_SEPARATORS = [";", "&&", "|", "$(", "`"]
    
    def get_rule_id(self) -> str:
        return "cmd_injection_separators"
    
    def get_name(self) -> str:
        return "Command Injection - Separators"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_tags(self) -> list[str]:
        return ["command-injection", "rce", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for command separators in query"""
        try:
            decoded_query = derived.get("decoded_query", "")
            
            # Skip if query too long
            if len(decoded_query) > 2048:
                return None
            
            for sep in self.CMD_SEPARATORS:
                if sep in decoded_query:
                    pos = decoded_query.find(sep)
                    start = max(0, pos - 15)
                    end = min(len(decoded_query), pos + 15)
                    evidence = decoded_query[start:end]
                    
                    return self._create_match(
                        confidence=0.65,
                        evidence=f"Command sep: {evidence}",
                        fields_used=["url", "query"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class LongQueryRule(BaseRule):
    """Detect suspiciously long query strings"""
    
    def get_rule_id(self) -> str:
        return "long_query"
    
    def get_name(self) -> str:
        return "Suspicious Long Query"
    
    def get_severity(self) -> Severity:
        return Severity.LOW
    
    def get_tags(self) -> list[str]:
        return ["abuse", "anomaly", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for abnormally long query strings"""
        try:
            query_len = derived.get("query_len", 0)
            
            if query_len > 512:
                # Adjust severity based on length
                if query_len > 2048:
                    confidence = 0.60
                else:
                    confidence = 0.45
                
                return self._create_match(
                    confidence=confidence,
                    evidence=f"Query length: {query_len} bytes",
                    fields_used=["url", "query"]
                )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


class SuspiciousUserAgentRule(BaseRule):
    """Detect known attack tool user agents"""
    
    SUSPICIOUS_UAS = [
        "sqlmap",
        "nikto",
        "acunetix",
        "nuclei",
        "nmap",
        "masscan",
        "burp",
        "nessus",
        "metasploit",
        "dirbuster",
    ]
    
    def get_rule_id(self) -> str:
        return "suspicious_user_agent"
    
    def get_name(self) -> str:
        return "Suspicious User Agent"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_tags(self) -> list[str]:
        return ["scanner", "tool", "web"]
    
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """Check for known attack tool user agents"""
        try:
            ua = derived.get("normalized_ua", "")
            
            for tool in self.SUSPICIOUS_UAS:
                if tool in ua:
                    # Truncate UA for evidence
                    evidence_ua = (event.user_agent or "")[:60]
                    
                    return self._create_match(
                        confidence=0.70,
                        evidence=f"Tool detected: {evidence_ua}",
                        fields_used=["user_agent"]
                    )
            
            return None
        except Exception as e:
            logger.error(f"Error in {self.rule_id}: {e}")
            return None


# Registry of all builtin rules
BUILTIN_RULES = [
    SQLiUnionSelectRule(),
    SQLiTautologyRule(),
    SQLiTimeBasedRule(),
    XSSScriptTagRawRule(),
    XSSScriptTagEncodedRule(),
    XSSEventHandlersRule(),
    TraversalRawRule(),
    TraversalEncodedRule(),
    SensitiveFileProbeRule(),
    CmdInjectionRule(),
    LongQueryRule(),
    SuspiciousUserAgentRule(),
]
