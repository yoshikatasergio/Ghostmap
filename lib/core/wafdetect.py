#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

GhostMap / Yoshi Edition addition
---------------------------------
WAF / WAF-as-a-Service detection (passive, fingerprint-only).

Purpose
-------
Identify which Web Application Firewall is in front of the target so the
operator can include the finding in their engagement report.

This module ONLY detects. It does NOT bypass, evade, or interact with
the WAF beyond the requests sqlmap was already going to send. The
fingerprints are read from response headers, cookies, and body strings
that the WAF itself sets — i.e. information the WAF is publishing about
itself.

Updated for 2026
----------------
- Cloudflare:  __cf_bm cookie (replaced __cfduid which was deprecated 2022),
               cf-ray header, "Just a moment..." challenge body
- AWS WAF:     x-amz-cf-id, x-amzn-RequestId, AWSALB cookies, "Request blocked"
- Akamai:      x-akamai-* headers, _abck / bm_sz / ak_bmsc cookies
- Imperva:     incap_ses_*, visid_incap_*, "Incapsula incident ID"
- F5 BIG-IP:   TS* cookies, BIGipServer*, X-WA-Info, "The requested URL was rejected"
- Wordfence:   x-firewall-block, "Wordfence", body fingerprints
- Sucuri:      x-sucuri-id, x-sucuri-cache, "Access Denied - Sucuri"
- Fastly (WAF mode): x-fastly-request-id, fastly-debug-* headers
- StackPath:   x-sp-* headers, "Access Denied" specific to StackPath
- Reblaze:     rbzid cookie, x-rbz-* headers
"""

from __future__ import print_function

import re


# Each fingerprint is a tuple:
#   (name, severity, header_patterns, cookie_patterns, body_patterns)
# header_patterns: list of compiled regexes matched against full headers blob
# cookie_patterns: list of cookie names (matched against Set-Cookie or Cookie)
# body_patterns:   list of compiled regexes matched against response body
#
# severity: how confident we are when we see this WAF
#   "high" = definitive (vendor-set header/cookie)
#   "med"  = probable (body fingerprint)
#   "low"  = possible (generic match)

WAF_FINGERPRINTS = [
    # ---------------------------------------------------------------
    # Cloudflare
    # ---------------------------------------------------------------
    {
        "name": "Cloudflare",
        "vendor": "Cloudflare, Inc.",
        "headers": [
            re.compile(r"(?i)\bcf-ray\s*:", re.MULTILINE),
            re.compile(r"(?i)\bcf-cache-status\s*:", re.MULTILINE),
            re.compile(r"(?i)\bserver\s*:\s*cloudflare", re.MULTILINE),
        ],
        "cookies": ["__cf_bm", "cf_clearance", "__cfduid", "cf_chl_"],
        "body": [
            re.compile(r"(?i)Just a moment\.\.\."),
            re.compile(r"(?i)Attention Required.*?Cloudflare"),
            re.compile(r"(?i)Cloudflare Ray ID"),
            re.compile(r"(?i)cdn-cgi/(challenge-platform|l/chk_jschl)"),
        ],
    },

    # ---------------------------------------------------------------
    # AWS WAF / AWS WAFv2
    # ---------------------------------------------------------------
    {
        "name": "AWS WAF",
        "vendor": "Amazon Web Services",
        "headers": [
            re.compile(r"(?i)\bx-amzn-(requestid|errortype)\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-amz-cf-id\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-amz-apigw-id\s*:", re.MULTILINE),
        ],
        "cookies": ["AWSALB", "AWSALBCORS", "aws-waf-token"],
        "body": [
            re.compile(r"(?i)<Code>WAFv?2?</Code>"),
            re.compile(r"(?i)Request blocked.*?AWS"),
            re.compile(r"(?i)AWS WAF"),
        ],
    },

    # ---------------------------------------------------------------
    # Akamai (Bot Manager / Kona Site Defender)
    # ---------------------------------------------------------------
    {
        "name": "Akamai",
        "vendor": "Akamai Technologies",
        "headers": [
            re.compile(r"(?i)\bx-akamai-", re.MULTILINE),
            re.compile(r"(?i)\bakamai-grn\s*:", re.MULTILINE),
            re.compile(r"(?i)\bakamai-cache-status\s*:", re.MULTILINE),
            re.compile(r"(?i)\bserver\s*:\s*AkamaiGHost", re.MULTILINE),
        ],
        "cookies": ["_abck", "bm_sz", "ak_bmsc", "bm_mi", "bm_sv"],
        "body": [
            re.compile(r"(?i)Reference\s*#?\s*\d+\.\w+\.akamai"),
            re.compile(r"(?i)akamai\s+request"),
        ],
    },

    # ---------------------------------------------------------------
    # Imperva (Incapsula / Cloud WAF)
    # ---------------------------------------------------------------
    {
        "name": "Imperva",
        "vendor": "Imperva, Inc. (Incapsula)",
        "headers": [
            re.compile(r"(?i)\bx-iinfo\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-cdn\s*:\s*Incapsula", re.MULTILINE),
        ],
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "body": [
            re.compile(r"(?i)Incapsula incident ID"),
            re.compile(r"(?i)_Incapsula_Resource"),
            re.compile(r"(?i)Imperva\s+(Incapsula|SecureSphere)"),
        ],
    },

    # ---------------------------------------------------------------
    # F5 BIG-IP ASM / Advanced WAF
    # ---------------------------------------------------------------
    {
        "name": "F5 BIG-IP",
        "vendor": "F5 Networks",
        "headers": [
            re.compile(r"(?i)\bx-wa-info\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-cnection\s*:", re.MULTILINE),
            re.compile(r"(?i)\bserver\s*:\s*BigIP", re.MULTILINE),
        ],
        "cookies": ["BIGipServer", "TS01", "TSPD_", "F5_ST"],
        "body": [
            re.compile(r"(?i)The requested URL was rejected"),
            re.compile(r"(?i)Please consult with your administrator"),
            re.compile(r"(?i)support ID is:\s*\d+"),
        ],
    },

    # ---------------------------------------------------------------
    # Wordfence
    # ---------------------------------------------------------------
    {
        "name": "Wordfence",
        "vendor": "Defiant, Inc.",
        "headers": [
            re.compile(r"(?i)\bx-firewall-block\s*:", re.MULTILINE),
        ],
        "cookies": ["wordfence_verifiedHuman", "wfvt_"],
        "body": [
            re.compile(r"(?i)Generated by Wordfence"),
            re.compile(r"(?i)Your access to this site has been limited"),
            re.compile(r"(?i)Wordfence is a security plugin"),
        ],
    },

    # ---------------------------------------------------------------
    # Sucuri
    # ---------------------------------------------------------------
    {
        "name": "Sucuri",
        "vendor": "Sucuri (GoDaddy)",
        "headers": [
            re.compile(r"(?i)\bx-sucuri-(id|cache|block)\s*:", re.MULTILINE),
            re.compile(r"(?i)\bserver\s*:\s*Sucuri", re.MULTILINE),
        ],
        "cookies": [],
        "body": [
            re.compile(r"(?i)Access Denied.*?Sucuri"),
            re.compile(r"(?i)Sucuri WebSite Firewall"),
        ],
    },

    # ---------------------------------------------------------------
    # Fastly (when in WAF / Next-Gen WAF mode)
    # ---------------------------------------------------------------
    {
        "name": "Fastly",
        "vendor": "Fastly, Inc.",
        "headers": [
            re.compile(r"(?i)\bfastly-debug-(path|ttl|state)\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-fastly-request-id\s*:", re.MULTILINE),
            re.compile(r"(?i)\bx-served-by\s*:\s*cache-", re.MULTILINE),
        ],
        "cookies": [],
        "body": [
            re.compile(r"(?i)Fastly error"),
        ],
    },

    # ---------------------------------------------------------------
    # StackPath / MaxCDN / Highwinds
    # ---------------------------------------------------------------
    {
        "name": "StackPath",
        "vendor": "StackPath",
        "headers": [
            re.compile(r"(?i)\bx-sp-(url|edge-host)\s*:", re.MULTILINE),
            re.compile(r"(?i)\bserver\s*:\s*StackPath", re.MULTILINE),
        ],
        "cookies": [],
        "body": [
            re.compile(r"(?i)stackpath.*?cdn"),
        ],
    },

    # ---------------------------------------------------------------
    # Reblaze
    # ---------------------------------------------------------------
    {
        "name": "Reblaze",
        "vendor": "Reblaze",
        "headers": [
            re.compile(r"(?i)\bx-rbz-", re.MULTILINE),
        ],
        "cookies": ["rbzid", "rbzsessionid"],
        "body": [
            re.compile(r"(?i)Current session has been terminated"),
            re.compile(r"(?i)reblaze"),
        ],
    },

    # ---------------------------------------------------------------
    # ModSecurity (open source) — kept for completeness
    # ---------------------------------------------------------------
    {
        "name": "ModSecurity",
        "vendor": "OWASP ModSecurity",
        "headers": [
            re.compile(r"(?i)\bmod_security|NOYB", re.MULTILINE),
        ],
        "cookies": [],
        "body": [
            re.compile(r"(?i)Mod_Security\s*\("),
            re.compile(r"(?i)<title>403 Forbidden</title>.*?ModSecurity", re.DOTALL),
        ],
    },
]


def detect(headers_text, set_cookie_text, body_text):
    """Try to detect WAF from response data.

    Args:
        headers_text:    raw HTTP headers blob (multi-line)
        set_cookie_text: Set-Cookie header values concatenated
        body_text:       response body (may be partial)

    Returns:
        list of dicts: [{"name", "vendor", "confidence", "evidence"}, ...]
        empty list if nothing matched.
    """
    results = []
    headers_text = headers_text or ""
    set_cookie_text = set_cookie_text or ""
    body_text = body_text or ""

    for fp in WAF_FINGERPRINTS:
        evidence = []
        confidence = None

        for pat in fp.get("headers", []):
            m = pat.search(headers_text)
            if m:
                evidence.append("header: %s" % m.group(0)[:60].strip())
                confidence = "high"
                break

        for cookie_name in fp.get("cookies", []):
            if cookie_name in set_cookie_text:
                evidence.append("cookie: %s" % cookie_name)
                confidence = confidence or "high"
                break

        if not confidence:
            for pat in fp.get("body", []):
                m = pat.search(body_text)
                if m:
                    evidence.append("body: %s" % m.group(0)[:60].strip())
                    confidence = "med"
                    break

        if evidence:
            results.append({
                "name": fp["name"],
                "vendor": fp["vendor"],
                "confidence": confidence or "low",
                "evidence": evidence,
            })

    return results


def format_detection_report(detections, color=True):
    """Render a human-friendly report. Used by the scan flow when a
    WAF is detected, or by the operator-facing block panel.
    """
    if not detections:
        return ""

    if color:
        DIM = "\033[01;30m"
        BOLD = "\033[01;37m"
        YELLOW = "\033[01;33m"
        CYAN = "\033[01;36m"
        RED = "\033[01;31m"
        RESET = "\033[0m"
    else:
        DIM = BOLD = YELLOW = CYAN = RED = RESET = ""

    lines = []
    lines.append("")
    lines.append("%s╔══[ %sWeb Application Firewall detected%s%s ]══════════════════════════╗%s" %
                 (DIM, CYAN, RESET, DIM, RESET))

    for d in detections:
        conf_color = RED if d["confidence"] == "high" else YELLOW
        lines.append("%s║%s  Vendor:      %s%s%s" %
                     (DIM, RESET, BOLD, d["name"], RESET))
        lines.append("%s║%s  Operator:    %s" % (DIM, RESET, d["vendor"]))
        lines.append("%s║%s  Confidence:  %s%s%s" %
                     (DIM, RESET, conf_color, d["confidence"], RESET))
        lines.append("%s║%s  Evidence:" % (DIM, RESET))
        for e in d["evidence"]:
            lines.append("%s║%s    - %s" % (DIM, RESET, e))
        lines.append("%s║%s" % (DIM, RESET))

    lines.append("%s║%s  %sImplications:%s" % (DIM, RESET, BOLD, RESET))
    lines.append("%s║%s    - Some payloads may be blocked at the edge." % (DIM, RESET))
    lines.append("%s║%s    - Rate limits may apply (consider --delay)." % (DIM, RESET))
    lines.append("%s║%s    - Detection accuracy may be reduced (false negatives)." % (DIM, RESET))
    lines.append("%s║%s" % (DIM, RESET))
    lines.append("%s║%s  %sFor your engagement report.%s" % (DIM, RESET, YELLOW, RESET))
    lines.append("%s║%s  %sNote:%s GhostMap will NOT auto-bypass." % (DIM, RESET, YELLOW, RESET))
    lines.append("%s║%s  %sIf your ROE explicitly authorizes bypass, see tamper/README.md%s" % (DIM, RESET, DIM, RESET))
    lines.append("%s║%s  %sfor combinations to try with --tamper.%s" % (DIM, RESET, DIM, RESET))
    lines.append("%s╚════════════════════════════════════════════════════════════════════╝%s" %
                 (DIM, RESET))
    lines.append("")
    return "\n".join(lines)


def suggest_tampers_for(waf_name):
    """Suggest tamper combinations known to be useful against this WAF.

    These are SUGGESTIONS for the operator. GhostMap does not apply them
    automatically. Returns list of suggested --tamper values.
    """
    suggestions = {
        "Cloudflare":  [
            "between,randomcase,charunicodeencode",
            "space2comment,charencode,apostrophenullencode",
            "modsecurityversioned,space2comment,randomcase",
        ],
        "AWS WAF":     [
            "between,randomcase,space2comment",
            "charunicodeencode,charencode",
        ],
        "Akamai":      [
            "between,space2randomblank,charunicodeencode",
            "randomcase,modsecurityversioned",
        ],
        "Imperva":     [
            "between,randomcase,charencode,space2randomblank",
            "modsecurityversioned,space2comment",
        ],
        "F5 BIG-IP":   [
            "between,space2mssqlblank,charunicodeencode,sp_password",
            "space2comment,randomcase",
        ],
        "Wordfence":   [
            "between,randomcase,space2comment",
            "charencode,modsecurityversioned",
        ],
        "ModSecurity": [
            "modsecurityversioned,space2comment,randomcase",
            "modsecurityzeroversioned,space2randomblank",
        ],
        "Sucuri":      [
            "between,charunicodeencode,space2comment",
        ],
        "Fastly":      [
            "between,randomcase,charencode",
        ],
        "StackPath":   [
            "between,randomcase,space2comment",
        ],
        "Reblaze":     [
            "between,randomcase,charunicodeencode",
        ],
    }
    return suggestions.get(waf_name, ["between,randomcase,space2comment"])
