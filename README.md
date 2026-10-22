# shadowphp

Shadow-IT discovery and PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure triage, in a single file.

`shadowphp` finds your brand's internet-facing web assets from free, open sources, checks which ones run PHP, and tells you which PHP versions are exposed to PHP2Shell. Assets that are not in your inventory are flagged as shadow IT.

It is a **detector, not an exploit.** It sends ordinary GET requests and reads the response headers the server already returns. It sends no malformed input and makes no attempt at code execution.

## Why

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) is an unauthenticated remote code execution flaw disclosed in October 2026, affecting nearly every PHP release from 5.4 through 8 (CVSS 9.2). The versions that close it are:

| Branch | Fixed in |
| --- | --- |
| 8.5.x | 8.5.12 |
| 8.4.x | 8.4.27 |
| 8.3.x | 8.3.36 |
| 8.2.x | 8.2.35 |
| 8.1.x and older | end of life, no fix |

For most organizations the dangerous hosts are not the patched, inventoried servers. They are the ones nobody is watching: a campaign site an agency spun up, a subdomain forgotten years ago, an old install on a subsidiary's hosting. `shadowphp` is built to surface exactly those.

## What it does

1. **Discover** assets from open sources, no API keys required:
   - Certificate Transparency logs via crt.sh (by domain and by organization name)
   - Wayback Machine CDX (historical and forgotten hosts)
   - `subfinder` and `amass` if they are installed (auto-detected, optional)
2. **Resolve** live hosts (`dnsx` if present, otherwise a built-in resolver)
3. **Probe** each host non-intrusively (`httpx` if present, otherwise a built-in prober)
4. **Triage** PHP exposure against the PHP2Shell fixed releases
5. **Flag** anything not in your known-assets list as `SHADOW-IT`, and anything on a different registrable domain as `OFF-DOMAIN`

It works with zero external tools installed. If `subfinder` / `dnsx` / `httpx` are on the PATH, it uses them for wider and richer coverage.

## Requirements

Python 3.7 or newer. Nothing else. No `pip install`.

Optional, for better coverage: [subfinder](https://github.com/projectdiscovery/subfinder), [dnsx](https://github.com/projectdiscovery/dnsx), [httpx](https://github.com/projectdiscovery/httpx), [amass](https://github.com/owasp-amass/amass).

## Usage

```bash
# simplest: one domain, everything automatic
python3 shadowphp.py example.com

# full run: domains + brand name + known-assets list + reports
python3 shadowphp.py example.com example.com.tr --org "Example Inc" \
    --known inventory.txt -o report.csv --json report.json

# discovery only, just list what was found
python3 shadowphp.py example.com --dry-run

# verify the logic
python3 shadowphp.py --self-test
```

### Useful flags

```
--org NAME        organization name for the crt.sh brand search (repeatable)
--known FILE      your inventory/CMDB (one host per line); others -> SHADOW-IT
--extra FILE      extra hosts to add to discovery
-o, --csv FILE    write a CSV report
--json FILE       write a JSON report
-c N              concurrency (default 30)
-t SECONDS        per-request timeout (default 10)
-k                skip TLS verification (built-in prober)
--no-tools        ignore subfinder/dnsx/httpx even if installed
--all             show PATCHED and NOT_PHP rows too
```

### The known-assets list

`--known` is optional and you create it yourself. It is just your inventory: one hostname or IP per line, lines starting with `#` ignored.

```
www.example.com
portal.example.com
10.0.5.12
```

Anything discovered that is not in this list is marked `SHADOW-IT`. Without `--known`, the tool still runs and ranks every PHP host by version risk, it just does not draw the shadow-IT line.

## Output

A risk-sorted table on screen, plus optional CSV/JSON.

| Status | Meaning | Action |
| --- | --- | --- |
| `EOL` | PHP 8.1 or older, no fix | upgrade or take offline |
| `VULNERABLE` | version below the fixed release | patch now |
| `UNKNOWN_PHP` | PHP detected, version hidden | verify manually |
| `PATCHED` | at or above the fixed release | none |
| `NOT_PHP` | no PHP signal | none |

Exit code is CI-friendly: `2` if anything is vulnerable or EOL, `1` if only unknown-PHP, `0` otherwise.

## Scope and responsible use

Discovery queries third-party services (crt.sh, Wayback) and then your targets. Run it only against assets you own or are explicitly authorized to assess. You are responsible for how you use it.

The tool does not exploit the vulnerability and will not be extended to do so.

## License

MIT. See [LICENSE](LICENSE).
