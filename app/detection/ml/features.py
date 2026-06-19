"""
Feature extraction for ML-based attack detection.
All operations are bounded and safe.
"""
from typing import Dict, Union
from app.models import LogEvent
from app.detection.utils.urltools import extract_query_params


# SQL keywords to detect
SQL_KEYWORDS = {
    'select', 'union', 'drop', 'insert', 'update', 'delete',
    'sleep', 'benchmark', 'information_schema', 'exec', 'execute'
}

# XSS tokens to detect
XSS_TOKENS = {
    '<script', 'onerror=', 'onload=', 'onclick=', 'onmouseover=',
    'javascript:', '<iframe', 'alert(', 'eval(', 'document.cookie'
}

# Path traversal tokens
TRAVERSAL_TOKENS = {
    '../', '..\\', '%2e%2e%2f', '%252e%252e%252f',
    '%2e%2e/', '%2e%2e%5c', '..%2f', '..%5c'
}

# Command injection tokens
CMD_TOKENS = {
    ';', '&&', '||', '|', '$(', '`',
    'wget', 'curl', 'bash', 'sh', 'powershell',
    'cmd.exe', 'whoami', 'nc ', 'netcat'
}

# Suspicious UA patterns
SUSPICIOUS_UA_PATTERNS = {
    'sqlmap', 'nikto', 'acunetix', 'nuclei', 'masscan',
    'nmap', 'burp', 'zaproxy', 'w3af', 'metasploit'
}


def extract_features(event: LogEvent, derived: dict) -> Dict[str, Union[float, int]]:
    """
    Extract bounded features from a log event.
    
    Args:
        event: LogEvent to extract features from
        derived: Derived context (from rule engine)
    
    Returns:
        Dictionary of numeric features
    
    Security:
        - All strings truncated before processing
        - Bounded loops and operations
        - No regex with unbounded backtracking
    """
    features = {}
    
    # Truncate inputs for safety
    url = (event.url or "")[:2048]
    ua = (event.user_agent or "")[:512]
    
    # 1. URL metrics
    features['url_len'] = min(len(url), 2048)
    
    # Extract query string
    query = url.split('?', 1)[1] if '?' in url else ""
    features['query_len'] = min(len(query), 2048)
    
    # Count parameters (bounded)
    try:
        params = extract_query_params(url, max_params=50)
        features['num_params'] = min(len(params), 50)
    except Exception:
        features['num_params'] = 0
    
    # 2. Character analysis (bounded)
    if len(url) > 0:
        # Special character ratio
        special_chars = sum(1 for c in url[:2048] if c in '!@#$%^&*()+=[]{}|\\:;"<>?,/')
        features['special_char_ratio'] = min(special_chars / len(url[:2048]), 1.0)
        
        # Percent-encoded tokens
        pct_encoded = url[:2048].lower().count('%')
        features['pct_encoded'] = min(pct_encoded, 100)
    else:
        features['special_char_ratio'] = 0.0
        features['pct_encoded'] = 0
    
    # 3. Attack pattern detection (bounded counts)
    url_lower = url[:2048].lower()
    
    # SQL keywords
    sql_count = sum(1 for keyword in SQL_KEYWORDS if keyword in url_lower)
    features['count_sql_keywords'] = min(sql_count, 20)
    
    # XSS tokens
    xss_count = sum(1 for token in XSS_TOKENS if token in url_lower)
    features['count_xss_tokens'] = min(xss_count, 20)
    
    # Traversal tokens
    traversal_count = sum(url_lower.count(token) for token in TRAVERSAL_TOKENS)
    features['count_traversal_tokens'] = min(traversal_count, 20)
    
    # Command injection tokens
    cmd_count = sum(1 for token in CMD_TOKENS if token in url_lower)
    features['count_cmd_tokens'] = min(cmd_count, 20)
    
    # 4. User agent indicators
    ua_lower = ua[:512].lower()
    
    # Suspicious UA patterns
    is_suspicious = 1 if any(pattern in ua_lower for pattern in SUSPICIOUS_UA_PATTERNS) else 0
    features['is_suspicious_ua'] = is_suspicious
    
    # Missing UA
    features['ua_missing'] = 1 if not ua or ua.strip() == "" else 0
    
    # 5. Status code indicators (guard against None)
    status = event.status if event.status is not None else 200
    features['status_is_4xx'] = 1 if 400 <= status < 500 else 0
    features['status_is_5xx'] = 1 if 500 <= status < 600 else 0
    
    # 6. Method indicators (guard against None)
    method = event.method if event.method is not None else "GET"
    features['method_is_post'] = 1 if str(method).upper() == "POST" else 0
    
    # 7. Path analysis (bounded)
    path = url.split('?')[0][:1024]
    
    # Path depth (count slashes, capped)
    path_depth = min(path.count('/'), 50)
    features['path_depth'] = path_depth
    
    # Login-related path
    path_lower = path.lower()
    has_login = 1 if any(kw in path_lower for kw in ['login', 'signin', 'auth']) else 0
    features['has_login_keyword'] = has_login
    
    return features
