"""
Minimal pipeline diagnostic - just verifies rules fire and storage writes.
"""
import sys, logging
logging.basicConfig(level=logging.ERROR)  # suppress noise
sys.path.insert(0, ".")

from datetime import datetime, timezone
from app.models import LogEvent, HTTPMethod
from app.detection.rules.registry import get_registry
from app.detection.rules.engine import run_rules

rules = get_registry().get_enabled_rules()
print(f"Rules loaded: {len(rules)}")


def make_event(url, status=200, ua="sqlmap/1.7.12"):
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        remote_ip="45.33.32.156",
        method=HTTPMethod.GET,
        url=url, status=status,
        user_agent=ua, body_bytes_sent=1234, request_time=0.1,
    )


# Test rule matching
sqli_event = make_event("/login?username=%27+OR+1%3D1--&password=anything")
matches = run_rules(sqli_event, rules)
print(f"SQLi URL -> {len(matches)} rule match(es)")
for m in matches:
    print(f"  rule_id={m.rule_id}  severity={m.severity}  tags={m.tags}")

xss_event = make_event("/?search=%3Cscript%3Ealert(1)%3C/script%3E")
matches2 = run_rules(xss_event, rules)
print(f"XSS URL  -> {len(matches2)} rule match(es)")

trav_event = make_event("/download?file=../../etc/passwd")
matches3 = run_rules(trav_event, rules)
print(f"Path traversal -> {len(matches3)} rule match(es)")

# Test full pipeline (storage write)
print("\n--- Full pipeline test ---")
from app.ingest import process_single_event
result = process_single_event(sqli_event)
print(f"Pipeline result: {list(result.keys())}")
risk = result.get("risk", {})
print(f"Risk score: {risk.get('risk_score')}  severity: {risk.get('severity')}")

# Check DB counts
print("\n--- DB row counts ---")
from app.storage.db import get_db_connection
conn = get_db_connection()
for table in ["events", "rule_matches", "risk_results", "alerts"]:
    n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print(f"  {table}: {n} rows")
