"""
Gemini Multi-LLM Judge — concurrent security analysis across 3 Gemini models.
Replaces the single-model Groq analyzer with a majority-voting judge panel.

Architecture:
    Panel: gemini-2.5-flash | gemini-2.5-pro | gemini-2.0-flash
    Execution: ThreadPoolExecutor (parallel API calls)
    Consensus: Majority vote on is_attack, averaged scores, frequency-weighted
               attack_type and severity
"""
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any, Dict, List, Optional, Tuple
from app.models import LogEvent
from .prompts import SYSTEM_PROMPT, REQUEST_TEMPLATE

logger = logging.getLogger(__name__)

# ── API Config ──────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("AI_API_KEY", "")
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

# Model panel — ordered by reasoning depth (heaviest last so flash results come first)
JUDGE_PANEL: List[str] = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.5-pro",
]

# Models that support / need thinkingBudget=0 for deterministic JSON output
_NO_THINKING_MODELS = {"gemini-2.5-flash", "gemini-2.5-pro"}

# Max retries on 429 rate-limit responses
_MAX_RETRIES = 2
_RETRY_DELAY = 1.5  # seconds between retries

# Per-call timeout in seconds (Gemini 2.5-pro can be a touch slower for thinking)
MODEL_TIMEOUT = 12.0

# Simple in-process cache: cache_key -> (result, expires_at)
_cache: Dict[str, Tuple[Dict, float]] = {}
CACHE_TTL_SECONDS = 300  # 5 minutes


def _make_cache_key(url: str, method: str, ip: str) -> str:
    clean_url = url[:200] if url else ""
    return f"{method}:{ip}:{clean_url}"


def _get_cached(key: str) -> Optional[Dict]:
    if key in _cache:
        result, expires_at = _cache[key]
        if time.time() < expires_at:
            return result
        del _cache[key]
    return None


def _set_cached(key: str, result: Dict) -> None:
    _cache[key] = (result, time.time() + CACHE_TTL_SECONDS)
    # Evict oldest entries when cache is large
    if len(_cache) > 500:
        oldest = sorted(_cache.keys(), key=lambda k: _cache[k][1])[:100]
        for k in oldest:
            del _cache[k]


# ── Heuristic fallback (offline, zero latency) ─────────────────────────────

def _heuristic_analyze(event: LogEvent, context: Dict) -> Dict[str, Any]:
    """
    Rule-based heuristic analyzer — used when all LLM calls fail.
    Provides meaningful output without any external API dependency.
    """
    url_lower = (event.url or "").lower()
    ua_lower  = (event.user_agent or "").lower()

    attack_type = "Normal"
    is_attack   = False
    severity    = "LOW"
    score       = 0.05
    explanation = "No suspicious patterns detected in this request."
    intent      = "Normal user activity"
    zero_day    = False

    sql_patterns = ["union select", "' or ", "\" or ", "sleep(", "benchmark(",
                    "waitfor delay", "1=1", "drop table"]
    xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert(", "%3cscript"]
    traversal    = ["../", "..\\", "%2e%2e", "..%2f", "/etc/passwd", "/etc/shadow"]
    cmd_inj      = [";ls", ";cat", ";wget", "$(", "`id`", "| whoami", "&&ls"]
    sens_files   = ["/.env", "/.git", "/wp-config", "/.aws", "/config.php",
                    "/server-status", "/phpmyadmin"]
    scanner_uas  = ["sqlmap", "nikto", "acunetix", "nuclei", "nmap", "masscan",
                    "burp", "nessus", "metasploit", "dirbuster", "zgrab"]

    if any(p in url_lower for p in sql_patterns):
        attack_type, is_attack, severity, score = "SQL Injection", True, "HIGH", 0.87
        explanation = "URL contains SQL injection patterns attempting to manipulate database queries."
        intent = "Extract or modify database records via SQL injection"

    elif any(p in url_lower for p in xss_patterns):
        attack_type, is_attack, severity, score = "XSS", True, "HIGH", 0.82
        explanation = "Cross-site scripting payload detected."
        intent = "Inject malicious script to steal session cookies or deface the application"

    elif any(p in url_lower for p in traversal):
        attack_type, is_attack, severity, score = "Path Traversal", True, "HIGH", 0.80
        explanation = "Directory traversal sequences found."
        intent = "Read sensitive server files such as configuration or credentials"

    elif any(p in url_lower for p in cmd_inj):
        attack_type, is_attack, severity, score = "Command Injection", True, "CRITICAL", 0.92
        explanation = "OS command injection sequences detected in the URL parameters."
        intent = "Execute arbitrary system commands via the web application"

    elif any(p in url_lower for p in sens_files):
        attack_type, is_attack, severity, score = "Reconnaissance", True, "MEDIUM", 0.65
        explanation = "Request targets known sensitive file paths."
        intent = "Discover exposed credentials, configuration, or admin interfaces"

    elif any(t in ua_lower for t in scanner_uas):
        attack_type, is_attack, severity, score = "Bot/Automation", True, "MEDIUM", 0.72
        explanation = "Known attack/scanning tool user agent detected."
        intent = "Automated vulnerability scanning of the web application"

    elif context.get("event_count", 1) > 30 and context.get("distinct_paths", 1) > 15:
        attack_type, is_attack, severity, score = "Reconnaissance", True, "MEDIUM", 0.60
        explanation = "High request volume across many unique endpoints — endpoint scanning behavior."
        intent = "Map application structure and discover hidden endpoints"
        zero_day = True

    elif event.status == 404 and context.get("event_count", 1) > 10:
        attack_type, is_attack, severity, score = "Reconnaissance", True, "LOW", 0.45
        explanation = "Repeated 404 responses suggest probing for non-existent resources."
        intent = "Brute-force discovery of valid paths and files"

    return {
        "is_attack":     is_attack,
        "attack_type":   attack_type,
        "confidence":    round(score, 3),
        "severity":      severity,
        "ai_score":      round(score, 3),
        "explanation":   explanation,
        "intent":        intent,
        "zero_day_risk": zero_day,
        "model_used":    "heuristic",
        "judge_results": [],
    }


# ── Per-model Gemini call ────────────────────────────────────────────────────

def _call_gemini_model(model: str, prompt: str) -> Optional[Dict[str, Any]]:
    """
    Call a single Gemini model and return parsed JSON response dict.
    Returns None on any failure (network error, parse error, invalid JSON).
    """
    if not GEMINI_API_KEY:
        return None

    url = GEMINI_BASE_URL.format(model=model, key=GEMINI_API_KEY)

    gen_config: Dict[str, Any] = {
        "responseMimeType": "application/json",
        "temperature": 0.1,
        "maxOutputTokens": 400,
    }
    # Disable chain-of-thought thinking on models that support it to guarantee
    # clean JSON output and reduce latency
    if model in _NO_THINKING_MODELS:
        gen_config["thinkingConfig"] = {"thinkingBudget": 0}

    payload = json.dumps({
        "contents": [
            {"parts": [{"text": prompt}]}
        ],
        "systemInstruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
        "generationConfig": gen_config,
    }).encode("utf-8")

    import urllib.request as req
    import urllib.error

    for attempt in range(_MAX_RETRIES + 1):
        try:
            request = req.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with req.urlopen(request, timeout=MODEL_TIMEOUT) as resp:
                body = json.loads(resp.read())

            # Extract text content from response
            content = body["candidates"][0]["content"]["parts"][0]["text"].strip()

            # Strip markdown fences if model added them despite responseMimeType
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)

            result = json.loads(content)
            result["model_used"] = f"google/{model}"
            return result

        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < _MAX_RETRIES:
                wait = _RETRY_DELAY * (2 ** attempt)
                logger.warning(f"Gemini '{model}' rate-limited (429), retrying in {wait}s...")
                time.sleep(wait)
                continue
            logger.warning(f"Gemini model '{model}' HTTPError {e.code}: {e.reason}")
            return None
        except Exception as e:
            logger.warning(f"Gemini model '{model}' call failed: {type(e).__name__}: {e}")
            return None

    return None


# ── Consensus aggregator ────────────────────────────────────────────────────

def _aggregate_consensus(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate multiple model outputs into a single consensus verdict.

    Strategy:
        is_attack      — majority vote (>= 50% True → True)
        zero_day_risk  — majority vote
        ai_score       — average of all outputs
        confidence     — average of all outputs
        severity       — frequency-weighted vote
        attack_type    — frequency-weighted vote
        explanation    — from the model with highest confidence matching majority
        intent         — same source as explanation
    """
    valid = [r for r in results if r and isinstance(r, dict)]
    if not valid:
        return {}

    models_used = [r.get("model_used", "unknown") for r in valid]

    # Majority vote on booleans
    attack_votes   = sum(1 for r in valid if r.get("is_attack",    False))
    zero_day_votes = sum(1 for r in valid if r.get("zero_day_risk", False))
    majority_threshold = len(valid) / 2.0
    is_attack_final   = attack_votes   > majority_threshold
    zero_day_final    = zero_day_votes > majority_threshold

    # Averaged scores
    ai_score_avg   = round(sum(float(r.get("ai_score",   0)) for r in valid) / len(valid), 3)
    confidence_avg = round(sum(float(r.get("confidence", 0)) for r in valid) / len(valid), 3)

    # Frequency-weighted vote for categorical fields
    def _majority_field(field: str, default: str) -> str:
        counts: Dict[str, int] = {}
        for r in valid:
            val = r.get(field, default)
            counts[val] = counts.get(val, 0) + 1
        return max(counts, key=counts.get, default=default)  # type: ignore

    severity_final    = _majority_field("severity",    "LOW")
    attack_type_final = _majority_field("attack_type", "Normal")

    # Find the most confident response that aligns with the majority verdict
    aligned = [r for r in valid if r.get("is_attack", False) == is_attack_final]
    if not aligned:
        aligned = valid
    best = max(aligned, key=lambda r: float(r.get("confidence", 0)))

    explanation_final = best.get("explanation", "No explanation provided.")
    intent_final      = best.get("intent",      "Unknown intent.")

    panel_label = "google/multi-judge [" + ", ".join(
        m.replace("google/", "") for m in models_used
    ) + "]"

    return {
        "is_attack":     is_attack_final,
        "attack_type":   attack_type_final,
        "confidence":    confidence_avg,
        "severity":      severity_final,
        "ai_score":      ai_score_avg,
        "explanation":   explanation_final,
        "intent":        intent_final,
        "zero_day_risk": zero_day_final,
        "model_used":    panel_label,
        "judge_results": [
            {
                "model":       r.get("model_used", "unknown"),
                "is_attack":   r.get("is_attack",   False),
                "attack_type": r.get("attack_type", "Normal"),
                "severity":    r.get("severity",    "LOW"),
                "ai_score":    r.get("ai_score",    0.0),
                "confidence":  r.get("confidence",  0.0),
            }
            for r in valid
        ],
    }


# ── Main analyzer class ─────────────────────────────────────────────────────

class AIAnalyzer:
    """
    Context-aware AI intent analyzer — Gemini Multi-LLM Judge.

    Queries gemini-2.5-flash, gemini-2.0-flash, and gemini-2.5-pro
    concurrently, then aggregates their outputs via majority voting.
    Falls back to lightweight heuristics when all API calls fail.
    """

    def __init__(self):
        self.llm_available = bool(GEMINI_API_KEY)
        if self.llm_available:
            logger.info(
                f"AI Analyzer initialized — Gemini Multi-LLM Judge "
                f"[{', '.join(JUDGE_PANEL)}]"
            )
        else:
            logger.info("AI Analyzer initialized with heuristic fallback (no API key)")

    def _build_context(
        self,
        event: LogEvent,
        rule_matches: List[Dict],
        behavior_matches: List[Dict],
    ) -> Dict[str, Any]:
        """Build behavioral context dict for the prompt."""
        context: Dict[str, Any] = {
            "event_count":    1,
            "distinct_paths": 1,
            "behavior_flags": [m.get("flag_id", "") for m in behavior_matches[:5]],
            "rule_matches":   [m.get("rule_id",  "") for m in rule_matches[:5]],
        }
        try:
            from app.detection.behavior.state import get_activity_store
            store = get_activity_store()
            events_60s = store.get_events(event.remote_ip, window_seconds=60)
            context["event_count"]    = len(events_60s)
            context["distinct_paths"] = len(set(e.get("path", "") for e in events_60s))
        except Exception:
            pass
        return context

    def analyze(
        self,
        event: LogEvent,
        rule_matches: Optional[List[Dict]] = None,
        behavior_matches: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a request for malicious intent using the Gemini judge panel.

        Returns a consensus dict with:
            is_attack, attack_type, confidence, severity, ai_score,
            explanation, intent, zero_day_risk, model_used, judge_results
        """
        rule_matches     = rule_matches     or []
        behavior_matches = behavior_matches or []

        context = self._build_context(event, rule_matches, behavior_matches)

        # Check cache first
        cache_key = _make_cache_key(event.url, str(event.method), event.remote_ip)
        cached = _get_cached(cache_key)
        if cached:
            logger.debug(f"AI cache hit for {event.remote_ip}")
            return cached

        result: Optional[Dict[str, Any]] = None

        if self.llm_available:
            try:
                prompt = REQUEST_TEMPLATE.format(
                    url            = (event.url          or "")[:500],
                    method         = event.method,
                    status         = event.status,
                    user_agent     = (event.user_agent   or "")[:200],
                    body_bytes     = event.body_bytes_sent or 0,
                    request_time   = event.request_time   or 0.0,
                    remote_ip      = event.remote_ip,
                    event_count    = context["event_count"],
                    distinct_paths = context["distinct_paths"],
                    behavior_flags = ", ".join(context["behavior_flags"]) or "None",
                    rule_matches   = ", ".join(context["rule_matches"])   or "None",
                )

                # Query all panel models concurrently
                raw_results: List[Optional[Dict]] = []
                with ThreadPoolExecutor(max_workers=len(JUDGE_PANEL)) as executor:
                    futures = {
                        executor.submit(_call_gemini_model, model, prompt): model
                        for model in JUDGE_PANEL
                    }
                    for future in as_completed(futures, timeout=MODEL_TIMEOUT + 2):
                        model_name = futures[future]
                        try:
                            raw_results.append(future.result())
                        except Exception as exc:
                            logger.warning(f"Judge panel: {model_name} raised {exc}")
                            raw_results.append(None)

                consensus = _aggregate_consensus(raw_results)
                if consensus:
                    result = consensus
                    logger.info(
                        f"Multi-LLM Judge consensus for {event.remote_ip}: "
                        f"is_attack={result['is_attack']} "
                        f"type={result['attack_type']} "
                        f"score={result['ai_score']}"
                    )

            except (FuturesTimeout, Exception) as e:
                logger.error(f"Multi-LLM Judge failed: {e}")

        # Heuristic fallback if all LLM calls failed
        if result is None:
            result = _heuristic_analyze(event, context)

        _set_cached(cache_key, result)
        return result


# ── Module-level singleton ──────────────────────────────────────────────────

_analyzer: Optional[AIAnalyzer] = None


def get_analyzer() -> AIAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = AIAnalyzer()
    return _analyzer


def analyze_request(
    event: LogEvent,
    rule_matches: Optional[List[Dict]] = None,
    behavior_matches: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Convenience function for one-off analysis."""
    return get_analyzer().analyze(event, rule_matches, behavior_matches)
