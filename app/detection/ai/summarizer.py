import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple
from app.core.config import settings

logger = logging.getLogger(__name__)

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}"

CACHE_TTL = 900  # 15 minutes
_summary_cache: Dict[str, Tuple[str, float]] = {}

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst AI. 
Your task is to analyze the high-level security statistics for the last 24 hours and write a concise, professional 2-3 sentence 'Morning Briefing' summary for the security team.
Do NOT use markdown. Do NOT use bullet points. Write a single short paragraph. 
Highlight any critical threats, the top attack vector, and provide a quick recommendation."""

def generate_dashboard_summary(stats: Dict[str, Any]) -> str:
    cache_key = "global_summary"
    
    if cache_key in _summary_cache:
        summary, expires_at = _summary_cache[cache_key]
        if time.time() < expires_at:
            logger.debug("AI Summary cache hit")
            return summary

    # Prevent LLM hallucinations if there are no alerts in the system
    alert_counts = stats.get('alert_counts', {})
    total_alerts = sum(alert_counts.values()) if isinstance(alert_counts, dict) else 0
    if total_alerts == 0:
        return "No threats or anomalous activities detected in the selected time window. All systems are operating normally with automated monitors active."

    api_key = settings.AI_API_KEY
    if not api_key:
        return "AI integration is not configured. Heuristic monitoring is active. Check the Recent Alerts table for any high severity events in the current window."

    prompt = f"""
Please summarize the following SOC statistics from the last 24 hours:

Total Alerts by Severity: {json.dumps(stats.get('alert_counts', {}))}
Top Attacking IPs: {json.dumps(stats.get('top_ips', [])[:3])}
Attack Type Distribution: {json.dumps(stats.get('attack_types', {}))}
"""

    gen_config = {
        "temperature": 0.3,
        "maxOutputTokens": 1024,
        "thinkingConfig": {"thinkingBudget": 0}
    }

    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "generationConfig": gen_config,
    }).encode("utf-8")

    try:
        url = GEMINI_BASE_URL.format(key=api_key)
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            body = json.loads(resp.read())
        
        content = body["candidates"][0]["content"]["parts"][0]["text"].strip()
        
        # Cache the result
        _summary_cache[cache_key] = (content, time.time() + CACHE_TTL)
        return content
        
    except Exception as e:
        logger.error(f"Failed to generate AI summary: {e}")
        return "Behavioral analysis active. Unable to reach AI judge for dynamic summary. Continue monitoring high-frequency IPs flagged in the current window."
