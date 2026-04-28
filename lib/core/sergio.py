#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

GhostMap / Yoshi Edition addition
---------------------------------
The --sergio diagnostic collector.

Purpose
-------
When the operator runs GhostMap with --sergio, this module:

  1. Installs a logging handler that captures WARNING/ERROR/CRITICAL
     events into an in-memory buffer.
  2. Captures stats: requests sent, errors, timeouts, status codes seen.
  3. Captures unhandled exceptions (tracebacks).
  4. At shutdown, writes a sanitized diagnostic file to the output path:
       ghostmap-sergio-<UTC timestamp>.txt

  The file is engineered so the fork maintainer can debug bugs without
  ever seeing:
    - The target host or full URL path
    - Sensitive parameter VALUES (only types and lengths are kept)
    - Cookie / Authorization / API key contents
    - Response bodies (only sizes & status codes)

  What IS kept (because it's needed to fix bugs):
    - Parameter NAMES (e.g. "id", "tipo", "opcion")
    - Python version, OS, optional libs available
    - Tracebacks from GhostMap code itself
    - Log messages from GhostMap / sqlmap
    - Counts and timings

This module is read-only at runtime aside from writing its own output
file. It does not phone home, does not upload anything, does not modify
anything outside the diagnostic file's path.
"""

from __future__ import print_function

import datetime
import logging
import os
import platform
import re
import sys
import threading
import time
import traceback


# Single global instance set up by setup_collector(). Module-level so that
# the logging handler and stat callbacks can reach it.
_collector = None
_collector_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

# Patterns we redact. Order matters: longer / more specific first.
_URL_PATTERN = re.compile(
    r"\b(?:https?|ftp)://[^\s'\"<>]+",
    re.IGNORECASE,
)

_HOST_HEADER_PATTERN = re.compile(
    r"(Host\s*:\s*)([^\s\r\n]+)",
    re.IGNORECASE,
)

_COOKIE_HEADER_PATTERN = re.compile(
    r"(Cookie\s*:\s*)([^\r\n]+)",
    re.IGNORECASE,
)

_AUTH_HEADER_PATTERN = re.compile(
    r"(Authorization\s*:\s*)([^\r\n]+)",
    re.IGNORECASE,
)

# IP addresses, but not version strings like Chrome/138.0.7204.158.
# We require the IP to be either at start/end of token, or surrounded
# by typical IP context (whitespace, common separators).
_IP_PATTERN = re.compile(
    r"(?<![\w./])\b(?:\d{1,3}\.){3}\d{1,3}\b(?![\w./])"
)

_EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def _redact_value_keep_shape(value):
    """Return a shape-preserving placeholder for `value`.

    Keeps the type (int/str) and approximate length so I can debug
    parser issues without seeing the actual content.

    Examples:
        "helloworld"         -> "<value:str:10chars>"
        "184"                -> "<value:int:3digits>"
        ""                   -> "<value:str:empty>"
    """
    if value is None:
        return "<value:null>"
    s = str(value)
    if not s:
        return "<value:str:empty>"
    if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
        return "<value:int:%ddigits>" % len(s)
    if re.match(r"^-?\d+\.\d+$", s):
        return "<value:float:%dchars>" % len(s)
    return "<value:str:%dchars>" % len(s)


def redact_url(url):
    """Redact a URL while preserving information useful for debugging.

    For "https://www4.example.com/path/to/api?id=184&tipo=helloworld":
    Output:
        "<scheme>://<host>/<path>?id=<value:int:3digits>&tipo=<value:str:10chars>"

    Parameter NAMES are kept; values are replaced with shape placeholders.
    """
    if not url:
        return url
    try:
        # Use urllib.parse for robustness (handles weird encoding).
        try:
            from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
        except ImportError:
            from urlparse import urlparse, parse_qsl, urlunparse
            from urllib import urlencode

        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        if qs:
            redacted_qs = [(name, _redact_value_keep_shape(v)) for name, v in qs]
            new_query = urlencode(redacted_qs, safe="<>:")
        else:
            new_query = ""

        return urlunparse((
            "<scheme>",
            "<host>",
            "/<path>",
            parsed.params,
            new_query,
            "",  # fragment removed
        ))
    except Exception:
        return "<unparseable_url:%dchars>" % len(url)


def redact_text(text):
    """Apply all redactions to an arbitrary text blob (e.g. a log line)."""
    if not text:
        return text

    # URLs first (before bare host patterns)
    text = _URL_PATTERN.sub(lambda m: redact_url(m.group(0)), text)
    # HTTP headers in raw request dumps
    text = _HOST_HEADER_PATTERN.sub(r"\1<host>", text)
    text = _COOKIE_HEADER_PATTERN.sub(r"\1<cookie:redacted>", text)
    text = _AUTH_HEADER_PATTERN.sub(r"\1<auth:redacted>", text)
    # Loose IP and email
    text = _IP_PATTERN.sub("<ip>", text)
    text = _EMAIL_PATTERN.sub("<email>", text)
    return text


# ---------------------------------------------------------------------------
# The collector
# ---------------------------------------------------------------------------

class SergioCollector(object):
    """Centralized in-memory bucket for the diagnostic dump."""

    MAX_LOG_LINES = 2000
    MAX_TRACEBACKS = 50

    def __init__(self):
        self.start_time = time.time()
        self.log_lines = []          # tuples (level_name, redacted_msg)
        self.tracebacks = []         # list of redacted traceback strings
        self.stats = {
            "requests_sent": 0,
            "responses_2xx": 0,
            "responses_3xx": 0,
            "responses_4xx": 0,
            "responses_5xx": 0,
            "timeouts": 0,
            "connection_errors": 0,
            "techniques_tried": [],
            "techniques_confirmed": [],
            "fallbacks_taken": [],   # e.g. "JSON regex failed -> urlencoded"
        }
        # Original CLI args, redacted. Special handling for --data and -d
        # which contain raw bodies that may have client values.
        self.cli_args = []
        _i = 0
        _argv = sys.argv[1:]
        while _i < len(_argv):
            _a = _argv[_i]
            if _a in ("--data", "-d") and _i + 1 < len(_argv):
                self.cli_args.append(_a)
                self.cli_args.append("<body:%dchars:redacted>" % len(_argv[_i + 1]))
                _i += 2
                continue
            if _a.startswith("--data="):
                self.cli_args.append("--data=<body:%dchars:redacted>" % (len(_a) - 7))
                _i += 1
                continue
            if _a in ("--cookie", "-H", "--header", "--auth-cred") and _i + 1 < len(_argv):
                self.cli_args.append(_a)
                self.cli_args.append("<redacted>")
                _i += 2
                continue
            self.cli_args.append(redact_text(_a))
            _i += 1
        # Build environment fingerprint
        self.environment = {
            "python":   "%d.%d.%d" % sys.version_info[:3],
            "platform": platform.platform(),
            "machine":  platform.machine(),
            "system":   platform.system(),
        }

    def add_log(self, level_name, message):
        if len(self.log_lines) >= self.MAX_LOG_LINES:
            return
        self.log_lines.append((level_name, redact_text(str(message))))

    def add_traceback(self, tb_text):
        if len(self.tracebacks) >= self.MAX_TRACEBACKS:
            return
        self.tracebacks.append(redact_text(tb_text))

    def note_request(self, status_code=None, timed_out=False, conn_error=False):
        self.stats["requests_sent"] += 1
        if timed_out:
            self.stats["timeouts"] += 1
        if conn_error:
            self.stats["connection_errors"] += 1
        if status_code is not None:
            try:
                bucket = "responses_%dxx" % (int(status_code) // 100)
                if bucket in self.stats:
                    self.stats[bucket] += 1
            except (ValueError, TypeError):
                pass

    def note_technique(self, name, confirmed=False):
        if name and name not in self.stats["techniques_tried"]:
            self.stats["techniques_tried"].append(name)
        if confirmed and name and name not in self.stats["techniques_confirmed"]:
            self.stats["techniques_confirmed"].append(name)

    def note_fallback(self, description):
        if description:
            entry = redact_text(str(description))
            if entry not in self.stats["fallbacks_taken"]:
                self.stats["fallbacks_taken"].append(entry)

    def render(self):
        """Render the diagnostic file as a string."""
        elapsed = time.time() - self.start_time
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        lines = []
        lines.append("=" * 72)
        lines.append("GhostMap --sergio diagnostic dump")
        lines.append("Generated: %s (UTC)" % ts)
        lines.append("Run duration: %.2f seconds" % elapsed)
        lines.append("=" * 72)
        lines.append("")
        lines.append("# This file is intentionally redacted.")
        lines.append("# Target host, full URL path, parameter VALUES,")
        lines.append("# Cookie / Authorization headers, and response bodies are")
        lines.append("# replaced with placeholders. Parameter NAMES, log messages")
        lines.append("# from GhostMap code, tracebacks, and stats are preserved.")
        lines.append("#")
        lines.append("# Send this file to the fork maintainer to debug issues.")
        lines.append("# Do NOT send raw sqlmap output, request files, or session")
        lines.append("# files -- those contain unredacted client data.")
        lines.append("")
        lines.append("[environment]")
        for k, v in sorted(self.environment.items()):
            lines.append("  %-12s %s" % (k + ":", v))
        lines.append("")
        lines.append("[command line] (redacted)")
        if self.cli_args:
            for a in self.cli_args:
                lines.append("  %s" % a)
        else:
            lines.append("  (none captured)")
        lines.append("")
        lines.append("[stats]")
        for k in (
            "requests_sent", "responses_2xx", "responses_3xx",
            "responses_4xx", "responses_5xx",
            "timeouts", "connection_errors",
        ):
            lines.append("  %-22s %d" % (k + ":", self.stats[k]))
        lines.append("  techniques_tried:      %s" %
                     ", ".join(self.stats["techniques_tried"]) or "(none)")
        lines.append("  techniques_confirmed:  %s" %
                     ", ".join(self.stats["techniques_confirmed"]) or "(none)")
        lines.append("")
        lines.append("[fallbacks taken]")
        if self.stats["fallbacks_taken"]:
            for f in self.stats["fallbacks_taken"]:
                lines.append("  - %s" % f)
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("[tracebacks]  (count: %d)" % len(self.tracebacks))
        if self.tracebacks:
            for i, tb in enumerate(self.tracebacks, 1):
                lines.append("--- traceback %d ---" % i)
                lines.append(tb.rstrip())
                lines.append("")
        else:
            lines.append("  (none)")
            lines.append("")
        lines.append("[log lines]  (capped at %d, captured: %d)" %
                     (self.MAX_LOG_LINES, len(self.log_lines)))
        for level, msg in self.log_lines:
            lines.append("  [%s] %s" % (level, msg))
        lines.append("")
        lines.append("=" * 72)
        lines.append("End of --sergio diagnostic dump")
        lines.append("=" * 72)
        return "\n".join(lines)

    def _gather_redaction_terms(self):
        """Gather all client-identifying strings that we'll globally
        replace in the rendered output as a final defense.

        This captures values that may have leaked through other layers
        (e.g. paths constructed by sqlmap that include the hostname,
        sqlmap log messages mentioning the URL host, etc.).
        """
        terms = set()
        try:
            from lib.core.data import conf
            url = getattr(conf, "url", None) or ""
            if url:
                terms.add(url)
                # Hostname only
                try:
                    from urllib.parse import urlparse
                except ImportError:
                    from urlparse import urlparse
                parsed = urlparse(url)
                if parsed.hostname:
                    terms.add(parsed.hostname)
                    # Variations: with/without www., with/without port
                    h = parsed.hostname
                    if h.startswith("www."):
                        terms.add(h[4:])
                    elif "." in h:
                        terms.add("www." + h)
                if parsed.netloc:
                    terms.add(parsed.netloc)
                    # Only the host part (no port)
                    if ":" in parsed.netloc:
                        terms.add(parsed.netloc.split(":")[0])
                # Try to resolve and add the IP too
                try:
                    import socket
                    if parsed.hostname:
                        ip = socket.gethostbyname(parsed.hostname)
                        terms.add(ip)
                except Exception:
                    pass

            # Also any host the operator may have set explicitly
            for attr in ("hostname", "ipv6", "host"):
                v = getattr(conf, attr, None)
                if v:
                    terms.add(str(v))
        except Exception:
            pass

        # Discard empties and very short strings (could match common words)
        return [t for t in terms if t and len(t) >= 4]

    def _apply_global_redaction(self, text):
        """Final defense: textually replace any client-identifying string
        that may have leaked into the rendered output."""
        terms = self._gather_redaction_terms()
        # Sort by length desc so longer matches replace first (full URL
        # before bare hostname).
        for term in sorted(terms, key=len, reverse=True):
            text = text.replace(term, "<target>")
        return text

    def write(self, output_dir):
        """Write the diagnostic file. Returns the path written."""
        try:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
        except OSError:
            output_dir = os.path.expanduser("~")

        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(output_dir, "ghostmap-sergio-%s.txt" % ts)

        # Render, then apply final global redaction of the captured host.
        rendered = self.render()
        rendered = self._apply_global_redaction(rendered)

        with open(path, "w") as f:
            f.write(rendered)
        return path


# ---------------------------------------------------------------------------
# Logging handler
# ---------------------------------------------------------------------------

class _SergioLogHandler(logging.Handler):
    def emit(self, record):
        if _collector is None:
            return
        try:
            level_name = record.levelname
            # Only capture interesting levels to avoid filling the buffer
            # with debug noise.
            if level_name not in ("WARNING", "ERROR", "CRITICAL", "INFO"):
                return
            msg = record.getMessage()
            with _collector_lock:
                _collector.add_log(level_name, msg)
                # If the record carries an exception, capture the traceback.
                if record.exc_info:
                    tb_str = "".join(traceback.format_exception(*record.exc_info))
                    _collector.add_traceback(tb_str)
        except Exception:
            # Never let the diagnostic handler itself crash sqlmap.
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_collector(logger):
    """Initialize the global collector and attach it to `logger`.

    Returns the collector. Idempotent: subsequent calls are no-ops.
    """
    global _collector
    with _collector_lock:
        if _collector is not None:
            return _collector
        _collector = SergioCollector()
        handler = _SergioLogHandler()
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
    return _collector


def get_collector():
    """Return the active collector or None if --sergio wasn't used."""
    return _collector


def is_active():
    return _collector is not None


def finalize(output_dir):
    """Write the diagnostic file. Returns path or None."""
    if _collector is None:
        return None
    try:
        return _collector.write(output_dir)
    except Exception as ex:
        return None


def install_excepthook():
    """Install a sys.excepthook that captures unhandled exceptions."""
    if _collector is None:
        return
    prev_hook = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):
        try:
            tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            with _collector_lock:
                if _collector is not None:
                    _collector.add_traceback(tb_str)
        except Exception:
            pass
        return prev_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook
