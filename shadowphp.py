#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shadowphp  -  Shadow-IT discovery + PHP2Shell (CVE-2026-109618/109619) triage

WHAT IT DOES
    1. DISCOVER  your brand's web assets from free, open sources (no API keys):
         - Certificate Transparency logs (crt.sh) by domain
         - crt.sh by organization name  (finds off-domain / agency sites)
         - Wayback Machine CDX (forgotten / historical hosts)
         - subfinder / amass if installed (auto-detected, optional)
    2. RESOLVE   live hosts  (dnsx if present, else built-in resolver)
    3. PROBE     each host non-intrusively  (httpx if present, else built-in)
    4. TRIAGE    PHP exposure against the PHP2Shell fixed releases:
         8.5.12 / 8.4.27 / 8.3.36 / 8.2.35   (8.1 and older = EOL)
    5. FLAG      anything NOT in your known-assets list as SHADOW-IT, and
                 anything on a different registrable domain as OFF-DOMAIN.

WHAT IT IS NOT
    A detector, not an exploit. It sends ordinary GET requests and reads the
    headers the server already returns. No malformed input, no RCE attempts.

AUTHORIZED USE ONLY
    Discovery touches third-party services (crt.sh, Wayback) and then your
    targets. Only run it against assets you own or are authorized to assess.

QUICK START
    python3 shadowphp.py example.com
    python3 shadowphp.py example.com example.com.tr --org "Example Corp" \\
        --known cmdb.txt -o report.csv --json report.json
    python3 shadowphp.py --self-test

LICENSE: MIT
"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error

__version__ = "1.0.0"

# ----------------------------- PHP2Shell logic -----------------------------
PATCHED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27),
           (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
EOL_MAX_MINOR = (8, 1)

VERSION_RE = re.compile(r"php/?\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", re.IGNORECASE)
PHP_HINT_RES = [
    re.compile(r"PHPSESSID", re.IGNORECASE),
    re.compile(r"X-Powered-By[\"'\s:]+PHP", re.IGNORECASE),
    re.compile(r"\bPHP\b", re.IGNORECASE),
    re.compile(r"\b(WordPress|Laravel|Joomla|Drupal|CodeIgniter|Symfony|phpMyAdmin|Bitrix|TYPO3|Magento|OpenCart|PrestaShop)\b",
               re.IGNORECASE),
    re.compile(r"(laravel_session|BITRIX_SM|XSRF-TOKEN|wp-content|wp-json)", re.IGNORECASE),
]
DEFAULT_UA = f"shadowphp/{__version__} (+non-intrusive attack-surface checker)"


def parse_version(blob):
    m = VERSION_RE.search(blob or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)) if m.group(3) else 0)


def php_hinted(blob):
    return any(p.search(blob or "") for p in PHP_HINT_RES)


def classify(version, hinted):
    if version:
        v = version
        branch = (v[0], v[1])
        if v[0] < 8 or branch <= EOL_MAX_MINOR:
            return ("EOL", "CRITICAL", f"PHP {v[0]}.{v[1]}.{v[2]} end-of-life, no fix")
        patched = PATCHED.get(branch)
        if patched is None:
            return ("UNKNOWN_BRANCH", "HIGH", f"PHP {v[0]}.{v[1]}.{v[2]} unknown 8.x branch, verify")
        if v < patched:
            return ("VULNERABLE", "HIGH",
                    f"PHP {v[0]}.{v[1]}.{v[2]} < {patched[0]}.{patched[1]}.{patched[2]} (unpatched)")
        return ("PATCHED", "INFO", f"PHP {v[0]}.{v[1]}.{v[2]} patched")
    if hinted:
        return ("UNKNOWN_PHP", "MEDIUM", "PHP detected, version hidden (expose_php=Off?), verify")
    return ("NOT_PHP", "INFO", "No PHP signal")


# ----------------------------- helpers -----------------------------
def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def registrable(host):
    """Very rough eTLD+1 (handles common 2-level TLDs like com.tr, co.uk)."""
    parts = host.lower().strip(".").split(".")
    two = {"com", "co", "org", "net", "gov", "edu", "ac", "mil"}
    if len(parts) >= 3 and parts[-2] in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def clean_host(h):
    h = (h or "").strip().lower()
    h = re.sub(r"^https?://", "", h)
    h = h.split("/")[0].split(":")[0]
    h = h.lstrip("*.").strip(".")
    if not h or " " in h or "." not in h:
        return None
    if not re.match(r"^[a-z0-9._-]+$", h):
        return None
    return h


def http_get_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def http_get_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# ----------------------------- discovery sources -----------------------------
def src_crtsh_domain(domain):
    out = set()
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        for row in http_get_json(url):
            for field in (row.get("name_value", ""), row.get("common_name", "")):
                for line in str(field).splitlines():
                    c = clean_host(line)
                    if c:
                        out.add(c)
    except Exception as e:
        log(f"  [crt.sh domain {domain}] failed: {type(e).__name__}")
    return out


def src_crtsh_org(org):
    """Brand-name search, catches off-domain certs registered to the company."""
    out = set()
    url = f"https://crt.sh/?q={urllib.parse.quote(org)}&output=json"
    try:
        for row in http_get_json(url):
            for field in (row.get("name_value", ""), row.get("common_name", "")):
                for line in str(field).splitlines():
                    c = clean_host(line)
                    if c:
                        out.add(c)
    except Exception as e:
        log(f"  [crt.sh org '{org}'] failed: {type(e).__name__}")
    return out


def src_wayback(domain):
    out = set()
    url = ("http://web.archive.org/cdx/search/cdx?"
           f"url=*.{urllib.parse.quote(domain)}&output=json&fl=original"
           "&collapse=urlkey&limit=5000")
    try:
        data = http_get_json(url)
        for row in data[1:]:  # first row is the header
            c = clean_host(row[0])
            if c:
                out.add(c)
    except Exception as e:
        log(f"  [wayback {domain}] failed: {type(e).__name__}")
    return out


def src_tool(tool, domain):
    """subfinder / amass passive, only if installed."""
    path = shutil.which(tool)
    if not path:
        return set()
    out = set()
    try:
        if tool == "subfinder":
            cmd = [path, "-d", domain, "-silent", "-all"]
        elif tool == "amass":
            cmd = [path, "enum", "-passive", "-d", domain]
        else:
            return set()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in p.stdout.splitlines():
            c = clean_host(line)
            if c:
                out.add(c)
    except Exception as e:
        log(f"  [{tool} {domain}] failed: {type(e).__name__}")
    return out


def discover(domains, orgs, use_tools):
    found = {}  # host -> set(sources)

    def add(hosts, label):
        for h in hosts:
            found.setdefault(h, set()).add(label)

    for d in domains:
        log(f"[discover] {d} via crt.sh ...")
        add(src_crtsh_domain(d), "crtsh")
        log(f"[discover] {d} via wayback ...")
        add(src_wayback(d), "wayback")
        if use_tools:
            if shutil.which("subfinder"):
                log(f"[discover] {d} via subfinder ...")
                add(src_tool("subfinder", d), "subfinder")
            if shutil.which("amass"):
                log(f"[discover] {d} via amass ...")
                add(src_tool("amass", d), "amass")
    for o in orgs:
        log(f"[discover] org '{o}' via crt.sh ...")
        add(src_crtsh_org(o), "crtsh-org")
    return found


# ----------------------------- resolve -----------------------------
def resolve_stdlib(hosts, concurrency):
    live = set()

    def one(h):
        try:
            socket.getaddrinfo(h, None)
            return h
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        for r in ex.map(one, hosts):
            if r:
                live.add(r)
    return live


def resolve_dnsx(hosts):
    path = shutil.which("dnsx") or os.path.expanduser("~/go/bin/dnsx")
    if not os.path.exists(path):
        return None
    try:
        p = subprocess.run([path, "-silent"], input="\n".join(hosts),
                           capture_output=True, text=True, timeout=600)
        return {clean_host(x) for x in p.stdout.splitlines() if clean_host(x)}
    except Exception as e:
        log(f"  [dnsx] failed: {type(e).__name__}")
        return None


# ----------------------------- probe -----------------------------
class Row:
    __slots__ = ("host", "url", "status_code", "server", "powered_by",
                 "php_version", "status", "risk", "note", "sources",
                 "shadow_it", "off_domain", "error")

    def __init__(self, host):
        self.host = host
        self.url = ""
        self.status_code = ""
        self.server = ""
        self.powered_by = ""
        self.php_version = None
        self.status = ""
        self.risk = ""
        self.note = ""
        self.sources = ""
        self.shadow_it = ""
        self.off_domain = ""
        self.error = ""

    def vstr(self):
        return ".".join(map(str, self.php_version)) if self.php_version else ""


def probe_stdlib(host, timeout, insecure):
    row = Row(host)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": DEFAULT_UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                row.url = resp.geturl()
                row.status_code = str(resp.status)
                hdr = resp.headers
                row.server = hdr.get("Server", "") or ""
                row.powered_by = hdr.get("X-Powered-By", "") or ""
                sc = "; ".join(hdr.get_all("Set-Cookie") or [])
                blob = " ".join([row.server, row.powered_by, sc])
                row.php_version = parse_version(blob)
                row.status, row.risk, row.note = classify(row.php_version, php_hinted(blob))
                return row
        except urllib.error.HTTPError as e:
            row.url = url
            row.status_code = str(e.code)
            row.server = e.headers.get("Server", "") if e.headers else ""
            row.powered_by = e.headers.get("X-Powered-By", "") if e.headers else ""
            blob = " ".join([row.server, row.powered_by])
            row.php_version = parse_version(blob)
            row.status, row.risk, row.note = classify(row.php_version, php_hinted(blob))
            return row
        except Exception as e:
            row.error = type(e).__name__
            continue
    row.status, row.risk, row.note = "ERROR", "INFO", "no response (https/http)"
    return row


def probe_httpx(hosts, timeout, insecure):
    """Use projectdiscovery httpx if present; return dict host->Row or None."""
    path = shutil.which("httpx") or os.path.expanduser("~/go/bin/httpx")
    if not os.path.exists(path):
        return None
    # Guard against the python 'httpx' CLI shadowing the Go tool
    try:
        v = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=20)
        if "projectdiscovery" not in (v.stdout + v.stderr).lower():
            log("  [httpx] found but not projectdiscovery build, using built-in prober")
            return None
    except Exception:
        return None
    cmd = [path, "-silent", "-td", "-server", "-title", "-sc", "-ip",
           "-irh", "-json", "-timeout", str(int(timeout))]
    if insecure:
        cmd.append("-no-color")  # httpx verifies loosely by default
    rows = {}
    try:
        p = subprocess.run(cmd, input="\n".join(hosts), capture_output=True,
                           text=True, timeout=1200)
        for line in p.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = clean_host(d.get("host") or d.get("input") or d.get("url") or "")
            if not host:
                continue
            r = Row(host)
            r.url = d.get("url", "")
            r.status_code = str(d.get("status_code", ""))
            r.server = d.get("webserver", "") or ""
            tech = d.get("tech") or []
            if isinstance(tech, str):
                tech = [tech]
            hdrs = d.get("header") or {}
            r.powered_by = ""
            if isinstance(hdrs, dict):
                r.powered_by = hdrs.get("x_powered_by") or hdrs.get("X-Powered-By") or ""
            blob = " ".join([r.server, r.powered_by, " ".join(map(str, tech)),
                             json.dumps(hdrs), d.get("title", "")])
            r.php_version = parse_version(blob)
            r.status, r.risk, r.note = classify(r.php_version, php_hinted(blob))
            rows[host] = r
    except Exception as e:
        log(f"  [httpx] failed: {type(e).__name__}, falling back to built-in")
        return None
    return rows


# ----------------------------- orchestration -----------------------------
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_known(path):
    known = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            t = line.strip().lower()
            if t and not t.startswith("#"):
                known.add(t.lstrip("*.").split("/")[0].split(":")[0])
    return known


def self_test():
    cases = [
        ((7, 4, 33), True, "EOL"), ((8, 1, 99), False, "EOL"),
        ((8, 2, 10), False, "VULNERABLE"), ((8, 2, 35), False, "PATCHED"),
        ((8, 4, 27), False, "PATCHED"), ((8, 9, 0), False, "UNKNOWN_BRANCH"),
        (None, True, "UNKNOWN_PHP"), (None, False, "NOT_PHP"),
    ]
    ok = True
    for ver, hint, exp in cases:
        got = classify(ver, hint)[0]
        if got != exp:
            ok = False
        print(f"  [{'ok ' if got == exp else 'FAIL'}] {ver} hint={hint} -> {got} ({exp})")
    assert clean_host("https://*.Foo.COM.tr/path") == "foo.com.tr"
    assert clean_host("not a host") is None
    assert registrable("a.b.example.com.tr") == "example.com.tr"
    assert registrable("x.example.com") == "example.com"
    assert parse_version("X-Powered-By: PHP/8.3.12") == (8, 3, 12)
    print("  [ok ] clean_host / registrable / parse_version")
    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="Shadow-IT discovery + PHP2Shell (CVE-2026-109618/109619) triage",
        epilog="Authorized assets only. Detects versions; does not exploit.")
    ap.add_argument("domains", nargs="*", help="root domain(s), e.g. example.com")
    ap.add_argument("--org", action="append", default=[],
                    help="organization name for crt.sh brand search (repeatable)")
    ap.add_argument("--known", help="file of known assets (CMDB); others flagged SHADOW-IT")
    ap.add_argument("--extra", help="file of extra hosts to add to discovery")
    ap.add_argument("-o", "--out", "--csv", dest="out", help="write CSV report")
    ap.add_argument("--json", dest="json_out", help="write JSON report")
    ap.add_argument("-c", "--concurrency", type=int, default=30)
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verify (built-in prober)")
    ap.add_argument("--no-tools", action="store_true",
                    help="ignore subfinder/dnsx/httpx even if installed")
    ap.add_argument("--dry-run", action="store_true", help="discovery only, list hosts and exit")
    ap.add_argument("--all", action="store_true", help="show PATCHED/NOT_PHP rows too")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"shadowphp {__version__}")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if not args.domains and not args.org and not args.extra:
        ap.error("give at least one domain, --org, or --extra file")

    use_tools = not args.no_tools
    log(f"shadowphp {__version__} | non-intrusive | authorized assets only")
    tools = [t for t in ("subfinder", "amass", "dnsx", "httpx")
             if use_tools and (shutil.which(t) or os.path.exists(os.path.expanduser(f"~/go/bin/{t}")))]
    log(f"external tools in use: {', '.join(tools) if tools else 'none (built-in only)'}\n")

    # 1) discover
    found = discover(args.domains, args.org, use_tools)
    if args.extra:
        with open(args.extra, encoding="utf-8", errors="replace") as f:
            for line in f:
                c = clean_host(line)
                if c:
                    found.setdefault(c, set()).add("extra")
    hosts = sorted(found)
    log(f"\n[discover] {len(hosts)} unique hostnames from open sources")

    if args.dry_run:
        for h in hosts:
            print(f"{h}\t{','.join(sorted(found[h]))}")
        sys.exit(0)

    if not hosts:
        log("nothing discovered, exiting")
        sys.exit(0)

    # 2) resolve
    live = None
    if use_tools:
        live = resolve_dnsx(hosts)
    if live is None:
        log("[resolve] using built-in resolver ...")
        live = resolve_stdlib(hosts, args.concurrency)
    live = sorted(live)
    log(f"[resolve] {len(live)} live hosts")
    if not live:
        sys.exit(0)

    # 3) probe
    rows = None
    if use_tools:
        log("[probe] trying httpx ...")
        rows = probe_httpx(live, args.timeout, args.insecure)
    if rows is None:
        log("[probe] using built-in prober ...")
        rows = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futs = {ex.submit(probe_stdlib, h, args.timeout, args.insecure): h for h in live}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                rows[r.host] = r
    # hosts that resolved but httpx skipped: fill as ERROR
    for h in live:
        rows.setdefault(h, Row(h))
        if not rows[h].status:
            rows[h].status, rows[h].risk, rows[h].note = "ERROR", "INFO", "no probe result"

    # 4) enrich: sources, shadow-it, off-domain
    known = load_known(args.known) if args.known else set()
    reg_domains = {registrable(d) for d in args.domains}
    for h, r in rows.items():
        r.sources = ",".join(sorted(found.get(h, {"resolved"})))
        if known:
            r.shadow_it = "SHADOW-IT" if h not in known else ""
        if reg_domains and registrable(h) not in reg_domains:
            r.off_domain = "OFF-DOMAIN"

    results = list(rows.values())
    results.sort(key=lambda r: (RISK_ORDER.get(r.risk, 9),
                                0 if r.shadow_it else 1, r.host))

    shown = [r for r in results if args.all or r.status in
             ("EOL", "VULNERABLE", "UNKNOWN_BRANCH", "UNKNOWN_PHP")]

    # 5) report
    from collections import Counter
    counts = Counter(r.status for r in results)
    print("=" * 76)
    print("shadowphp report  |  PHP2Shell CVE-2026-109618 / CVE-2026-109619")
    print("=" * 76)
    print(f"discovered: {len(hosts)} | live: {len(live)} | flagged: {len(shown)}")
    for st in ("EOL", "VULNERABLE", "UNKNOWN_BRANCH", "UNKNOWN_PHP",
               "PATCHED", "NOT_PHP", "ERROR"):
        if counts.get(st):
            print(f"  {st:<15}: {counts[st]}")
    if known:
        print(f"  SHADOW-IT       : {sum(1 for r in results if r.shadow_it)}")
    print(f"  OFF-DOMAIN      : {sum(1 for r in results if r.off_domain)}")
    print("-" * 76)
    for r in shown:
        tags = " ".join(t for t in (r.shadow_it, r.off_domain) if t)
        print(f"[{r.risk:<8}] {r.status:<14} {r.vstr():<8} {r.host:<38.38} {tags} {r.note}")
    if not shown:
        print("No vulnerable or unknown-PHP hosts found.")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["risk", "status", "shadow_it", "off_domain", "php_version",
                        "host", "url", "status_code", "server", "x_powered_by",
                        "sources", "note", "error"])
            for r in results:
                w.writerow([r.risk, r.status, r.shadow_it, r.off_domain, r.vstr(),
                            r.host, r.url, r.status_code, r.server, r.powered_by,
                            r.sources, r.note, r.error])
        print(f"\nCSV written: {args.out}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump([{k: getattr(r, k) for k in
                        ("risk", "status", "shadow_it", "off_domain", "host", "url",
                         "status_code", "server", "powered_by", "sources", "note", "error")}
                       | {"php_version": r.vstr()} for r in results],
                      f, indent=2, ensure_ascii=False)
        print(f"JSON written: {args.json_out}")

    if any(r.status in ("EOL", "VULNERABLE", "UNKNOWN_BRANCH") for r in results):
        sys.exit(2)
    if any(r.status == "UNKNOWN_PHP" for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
