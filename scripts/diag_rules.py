"""
Diagnostic: test rule matching and single-event pipeline on attack URLs.
"""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timezone
from app.models import LogEvent, HTTPMethod

TESTS = [
    ("/search?q='+OR+'x'%3D'x",                                         "SQLI"),
    ("/login?username='+OR+1%3D1--&password=anything",                   "SQLI"),
    ("/products?id=1+UNION+SELECT+null,username,password+FROM+users--",  "SQLI"),
    ("/?search=<script>alert('xss')</script>",                           "XSS"),
    ("/download?file=../../etc/passwd",                                  "PATH TRAVERSAL"),
    ("/%2e%2e/%2e%2e/%2e%2e/etc/passwd",                                 "PATH TRAVERSAL"),
    ("/api/exec?cmd=ls+-la+/",                                           "CMDI"),
    ("/.env",                                                             "SCANNER"),
    ("/wp-admin/",                                                        "SCANNER"),
    ("/",                                                                 "NORMAL"),
    ("/api/products",                                                     "NORMAL"),
]


def make_event(path: str) -> LogEvent:
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        remote_ip="45.33.32.156",
        method=HTTPMethod.GET,
        url=path,
        status=200,
        user_agent="sqlmap/1.7.12#stable",
        body_bytes_sent=1234,
        request_time=0.1,
    )


print("Loading rules...")
from app.detection.rules.registry import get_registry
from app.detection.rules.engine import run_rules, derive_context

rules = get_registry().get_enabled_rules()
print(f"Rules loaded: {len(rules)}\n")

for path, label in TESTS:
    try:
        event = make_event(path)
        matches = run_rules(event, rules)
        print(f"[{label:15}] {path[:60]:60s} -> {len(matches)} match(es)")
        for m in matches:
            print(f"              rule={m.rule_id}  sev={m.severity}  type={m.attack_type}")
    except Exception as e:
        print(f"[{label:15}] ERROR: {e}")

print("\n--- Testing full process_single_event ---")
from app.ingest import process_single_event
event = make_event("/login?username='+OR+1%3D1--&password=anything")
result = process_single_event(event)
print(f"Result keys: {list(result.keys())}")
if "risk" in result:
    print(f"Risk: score={result['risk'].get('risk_score')} severity={result['risk'].get('severity')}")
