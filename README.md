<div align="center">

<img src="https://i.postimg.cc/tCTDGpN6/imagen.png" alt="GhostMap" width="420"/>

# GhostMap — Yoshi Edition

```
   ________               __  __  ___
  / ____/ /_  ____  _____/ /_/  |/  /___ _____
 / / __/ __ \/ __ \/ ___/ __/ /|_/ / __ `/ __ \
/ /_/ / / / / /_/ (__  ) /_/ /  / / /_/ / /_/ /
\____/_/ /_/\____/____/\__/_/  /_/\__,_/ .___/
                                      /_/
```

### *Adaptive SQL Injection & Database Audit Framework*

**Engagement-grade fork of [sqlmap](https://sqlmap.org), built for working pentesters.**

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-red.svg?style=flat-square)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Python](https://img.shields.io/badge/python-2.7%20%7C%203.x-yellow.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Based on sqlmap](https://img.shields.io/badge/based%20on-sqlmap%201.10.4.13%23dev-1f6feb.svg?style=flat-square)](https://github.com/sqlmapproject/sqlmap)
[![Made in Peru](https://img.shields.io/badge/Made%20in-Peru%20🇵🇪-D91023.svg?style=flat-square)](https://www.linkedin.com/in/sergio-yoshikata/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sergio%20Yoshikata-0A66C2.svg?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sergio-yoshikata/)
[![Maintained](https://img.shields.io/badge/maintained-yes-2ea44f.svg?style=flat-square)](https://github.com/yoshikatasergio/Ghostmap/commits/main)

</div>

---

## What is GhostMap?

GhostMap is a maintained fork of [sqlmap](https://sqlmap.org) (`v1.10.4.13#dev`) with **engagement-grade UX improvements** for working pentesters. The diff is intentionally narrow:

- Better defaults
- Redacted diagnostic dumps that don't leak client data
- Multi-client output separation
- Modern WAF detection (2026 fingerprints)
- A polished `--os-shell` that survives time-based blind injections

> [!IMPORTANT]
> **What GhostMap is NOT:** a stealth tool. It does **not** add new RCE vectors, automated WAF bypass, lateral movement, or post-exploitation primitives that sqlmap upstream doesn't already have. *Detection-first, operator-decides* philosophy.

---

## Why GhostMap

| Pain point in upstream sqlmap | What GhostMap does |
|---|---|
| Output mixes across engagements | `--engagement <client>` separates everything |
| Hard to share bugs without leaking client data | `--sergio` produces redacted diagnostic dumps |
| `--os-shell` floods you with `[INFO] retrieved:` spam | Clean output + footer with exit code, time, chars |
| No idea if RCE is on the same box as the web server | `!web-loc` correlates IP, webroot and process |
| Time-based blind makes `--os-shell` unusable | Auto-skip heavy fingerprint, `!quick` instead (~5s) |
| Outdated WAF detection | 11 vendors fingerprinted for 2026 |
| Generic `sqlmap` UA in client logs | `GhostMap/<v>` honest bot UA, identifiable |
| CMD breaks the banner with weird Unicode | Pure ASCII slant, renders in cp850 natively |

---

## Features

### 🎯 Diagnostic & Reporting

- **`--sergio`** — Redacted diagnostic dumps. Whitelist + global replace at write time. Safe to share for bug reports without leaking client URLs, parameter values, cookies, or response bodies.
- **`--engagement <name>`** — Multi-client output separation under `output/<engagement>/<host>/`. Stop mixing client data.
- **Auto-transcript** — Every `--os-shell` session is recorded by default. Great for engagement reports.
- **Branded honest User-Agent** — Default `GhostMap/<version> (+homepage)` instead of upstream's. Identifies the tool, doesn't impersonate browsers.

### 🛡️ WAF Detection 2026

11 vendor fingerprints, **detection only**:

| Vendor | Notable signal |
|---|---|
| **Cloudflare** | `cf-ray` header, `__cf_bm` cookie (replaces deprecated `__cfduid`) |
| **AWS WAF** | `x-amz-cf-id`, `aws-waf-token` cookie |
| **Akamai** | `_abck`, `bm_sz`, `ak_bmsc` cookies |
| **Imperva** | `incap_ses_*`, `visid_incap_*` cookies |
| **F5 BIG-IP** | `BIGipServer*`, `TS01*` cookies |
| **Wordfence** | `x-firewall-block` header |
| **Sucuri** | `x-sucuri-*` headers |
| **Fastly** | `fastly-debug-*` headers |
| **StackPath** | `x-sp-*` headers |
| **Reblaze** | `rbzid` cookie |
| **ModSecurity** | classic open-source signatures |

When a WAF is detected, GhostMap shows a **detection panel** (vendor / confidence / evidence). When a WAF actively blocks payloads, GhostMap shows a **suggestion panel** with `--tamper` combinations the operator can apply manually if their Rules of Engagement authorize bypass.

> [!NOTE]
> GhostMap **does not auto-bypass WAFs**. The operator decides.

### 💻 GhostMap OS Shell

Time-based-aware shell with operator-friendly extras:

| Command | What it does |
|---|---|
| `!quick` | Quick IP correlation only (~5s, blind-safe) |
| `!probe` | Full environment fingerprint (opt-in) |
| `!web-loc` | Detect if RCE host == web server (IP, webroot, process) |
| `!ip` | IP correlation summary |
| `!last` | Re-show last command output (no re-exec) |
| `!note <text>` | Append timestamped note to transcript |
| `!save <cmd>` | Run cmd & save output to file |
| `!hist [text]` | Show / search history |
| `!transcript on/off` | Toggle session recording (ON by default) |
| `!noconfirm` | Skip command preview (DANGER) |
| `!info` | Show target context |
| `!clear` | Clear screen |
| `?` / `help` | Show full help |

Every command shows a discreet footer: `[ok · 1.23s · 87 chars retrieved]` so you know exactly what happened.

### 🔧 Tampers

69 documented payload-transformation primitives in `tamper/`. EOL `bluecoat.py` removed (Symantec Blue Coat acquired by Broadcom 2016). See [`tamper/README.md`](./tamper/README.md) for combinations by stack.

### 🪟 Compatibility

- **Python** 2.7 / 3.x (3.13 tested)
- **Windows CMD** — banner uses pure ASCII, renders in default cp850 / cp1252 codepages without `chcp 65001`
- **CP850 auto-decode** for Spanish/Latin Windows targets — no more `?` instead of accents

---

## Installation

```bash
git clone --depth 1 https://github.com/yoshikatasergio/Ghostmap.git ghostmap
cd ghostmap
python sqlmap.py --version
```

No build, no compile, no dependencies beyond Python.

---

## Usage

### Basic scan with engagement separation

```bash
python sqlmap.py -u "https://target.example/?id=1" --batch \
    --engagement client-x \
    --random-agent
```

### Scan with redacted diagnostic dump (for bug reports)

```bash
python sqlmap.py -u "https://target.example/?id=1" --batch --sergio
```

### Get full options list

```bash
python sqlmap.py -hh
```

For sqlmap-specific usage, consult the [original sqlmap manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage). All upstream functionality is preserved.

---

## Reporting bugs

For **GhostMap-specific** issues (anything mentioning `--sergio`, `--engagement`, `!web-loc`, `!quick`, `!ip`, the GhostMap banner, OS Shell improvements, the WAF detection panel):

→ https://github.com/yoshikatasergio/Ghostmap/issues

> [!TIP]
> **Please attach the `--sergio` diagnostic dump.** It is engineered to be safe to share — it does NOT contain your target's URL, parameter values, cookies, or response bodies.

For **upstream sqlmap** issues (core detection engine, payloads, DBMS support):

→ https://github.com/sqlmapproject/sqlmap/issues

---

## Links

|  |  |
|---|---|
| 📦 Repository | https://github.com/yoshikatasergio/Ghostmap |
| 🐛 Issue tracker | https://github.com/yoshikatasergio/Ghostmap/issues |
| 👤 Author | [Sergio Yoshikata Mifflin](https://www.linkedin.com/in/sergio-yoshikata/) |
| 🏛️ Original sqlmap | https://sqlmap.org |
| ⬆️ Upstream repository | https://github.com/sqlmapproject/sqlmap |

---

## License

[GPLv2](./LICENSE), inherited from sqlmap upstream.

- Original sqlmap by **Bernardo Damele A.G.** & **Miroslav Stampar**
- GhostMap modifications by **Sergio Yoshikata Mifflin**

---

## Credits

GhostMap stands on the shoulders of [sqlmap](https://github.com/sqlmapproject/sqlmap), the original SQL injection automation framework. All upstream detection logic, payloads, DBMS support, and the underlying engine come from sqlmap. GhostMap curates and improves the operator-facing experience for engagement workflows — nothing more.

<div align="center">

**Made with care in Lima, Peru 🇵🇪**

<br>

[![LinkedIn](https://img.shields.io/badge/Connect%20on-LinkedIn-0A66C2.svg?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sergio-yoshikata/)

</div>
