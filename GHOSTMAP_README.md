# GhostMap — Yoshi Edition (v5)

A maintained fork of [sqlmap](https://sqlmap.org) (v1.10.4.13#dev) with
quality-of-life improvements for engagement-grade SQL-injection auditing.

**Modified by:** Sergio Yoshikata Mifflin <yoshikatasergio@gmail.com>
**Upstream:** sqlmap by Bernardo Damele A.G. & Miroslav Stampar (GPLv2)
**Homepage:** https://github.com/yoshikatasergio/

## What this fork is, and is not

GhostMap is **sqlmap with curated UX improvements** for working
pentesters. It is **not** a stealth/evasion tool. It does **not** add
new RCE vectors, automated WAF bypass, lateral movement, or post-
exploitation primitives that the upstream tool doesn't already have.

The diff is intentionally narrow: better defaults, better operator
experience, better reporting context. That's it.

## v5 highlights

### `--sergio` flag — redacted diagnostic dumps
Sanitized diagnostic file for sharing with the fork maintainer to
debug bugs **without leaking client data**. Target host, full URL
paths, parameter values, cookies, and Authorization headers are
replaced with placeholders. Parameter NAMES, log messages,
tracebacks, and counters are kept.

The dump applies a **whitelist + global replace** layer at write
time, ensuring the captured target host string is removed even if it
leaked into a sqlmap log message or output path.

### `--engagement <name>` flag — multi-client output separation
Output goes to `output/<engagement>/<host>/...` instead of the shared
output root.

### GhostMap OS Shell (replaces upstream's `--os-shell`)
- Pre-flight passive environment fingerprint (read-only).
- **v5: blind-technique aware** — when sqlmap is using time-based or
  boolean-blind, the heavy fingerprint is skipped automatically and
  `!quick` / `!probe` are offered as opt-in.
- Branded prompt: `ghostmap[mssql@windows:xp_cmdshell]#`
- Pre-execution preview of every command (operator can abort).
- Confirmation prompt for dangerous patterns (`rm -rf`, `format`, ...).
- **Transcript ON by default** — every command and output is recorded
  to a session log automatically.
- Special commands: `?` `!info` `!quick` `!probe` `!web-loc` `!ip`
  `!last` `!note` `!transcript` `!save` `!hist` `!replay`
  `!noconfirm` `!clear` `x|q|exit`

### Updated WAF detection (2026)
A new `lib/core/wafdetect.py` module identifies which WAF is in
front of the target. Ten vendor fingerprints updated for 2026:

| WAF | Notable signal |
|---|---|
| Cloudflare | `cf-ray` header, `__cf_bm` cookie |
| AWS WAF | `x-amz-cf-id`, `aws-waf-token` cookie |
| Akamai | `_abck`, `bm_sz`, `ak_bmsc` cookies |
| Imperva | `incap_ses_*`, `visid_incap_*` cookies |
| F5 BIG-IP | `BIGipServer*`, `TS01*` cookies |
| Wordfence | `x-firewall-block` header |
| Sucuri | `x-sucuri-*` headers |
| Fastly | `fastly-debug-*` headers |
| StackPath | `x-sp-*` headers |
| Reblaze | `rbzid` cookie |

Detection only. **No automatic bypass.** When a block is detected,
GhostMap shows a **suggestion panel** with `--tamper` combinations
the operator can apply manually if their Rules of Engagement
authorize WAF bypass.

### Branded User-Agent
Default User-Agent header is now:
```
GhostMap/<version> (+https://github.com/yoshikatasergio/)
```
Override with `--random-agent` or `--user-agent` as needed.

### Curated tampers
- Removed `bluecoat.py` (Blue Coat acquired by Broadcom 2016, EOL).
- Added `tamper/README.md` with categorized table of all 69 tampers
  and recommended combinations by stack.

### CMD compatibility
Banner uses ASCII slant figlet font + ASCII-only box-drawing
characters; renders correctly in Windows CMD with default cp850 /
cp1252 codepages without requiring `chcp 65001`.

## Installation

Same as upstream sqlmap:

```bash
git clone https://github.com/yoshikatasergio/ghostmap.git
cd ghostmap
python sqlmap.py --version
```

Requires Python 2.6+ or 3.x (3.13 tested).

## Usage examples

```bash
# Standard scan
python sqlmap.py -u "https://target.example.com/?id=1" --batch

# With redacted diagnostic dump
python sqlmap.py -u "..." --batch --sergio

# Multi-client engagement separation
python sqlmap.py -u "..." --batch --engagement client-x

# Random UA for engagements that need it
python sqlmap.py -u "..." --batch --random-agent --engagement client-x
```

## License

GPLv2, inherited from sqlmap upstream. See `LICENSE`.

## Reporting issues

For upstream sqlmap bugs: https://github.com/sqlmapproject/sqlmap

For GhostMap-specific bugs: open an issue at
https://github.com/yoshikatasergio/. When reporting GhostMap bugs,
please include the `--sergio` dump.
