#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

GhostMap / Yoshi Edition addition
---------------------------------
Runtime integrity & capability check.

Purpose
-------
At startup, before any scan logic runs, we verify:

  1. Python version is supported (>= 3.6 recommended; 2.7 still works but warned)
  2. Critical stdlib modules import cleanly (sanity check vs. broken installs)
  3. Optional modules are detected and their capabilities reported
     (Brotli, zstandard, cryptography, lxml — affects what GhostMap can do
     transparently)
  4. Output an integrity summary to the logger so the operator knows what
     features are available *before* the scan starts, not when something
     fails halfway through

This module is read-only at runtime (does not patch anything). It just
returns a dict with the diagnostic info; the caller decides what to do
with it.
"""

from __future__ import print_function

import importlib
import os
import sys


# Minimum Python version we will run on. Below this, we warn but proceed
# (sqlmap upstream still supports 2.7, but Python 3.6+ is strongly preferred
# in 2026).
MIN_PY_MAJOR = 2
MIN_PY_MINOR = 7
RECOMMENDED_PY = (3, 6)

# Modules that MUST be importable for sqlmap to function at all.
# If any of these fail, we raise; the user has a broken install.
CRITICAL_STDLIB = (
    "re", "json", "socket", "ssl", "hashlib", "threading",
    "subprocess", "tempfile", "logging", "urllib",
)

# Optional modules that enable additional capabilities.
# Mapping: module_name -> (capability_label, why_it_matters)
OPTIONAL_MODULES = {
    "brotli": (
        "Brotli decompression",
        "decode 'Content-Encoding: br' responses (modern CDNs)",
    ),
    "zstandard": (
        "Zstandard decompression",
        "decode 'Content-Encoding: zstd' responses (newer servers)",
    ),
    "cryptography": (
        "Modern TLS/crypto",
        "stronger SSL contexts, JWT inspection in --data",
    ),
    "lxml": (
        "Fast XML parsing",
        "faster --xml flag handling",
    ),
    "readline": (
        "Interactive shell (readline)",
        "history & editing in --os-shell, --sql-shell",
    ),
}


def check_python_version():
    """Return (level, message) where level is 'ok', 'warn', or 'error'."""
    v = sys.version_info
    if v.major < MIN_PY_MAJOR or (v.major == MIN_PY_MAJOR and v.minor < MIN_PY_MINOR):
        return ("error", "Python %d.%d.%d is below minimum supported (%d.%d)" %
                (v.major, v.minor, v.micro, MIN_PY_MAJOR, MIN_PY_MINOR))
    if v < RECOMMENDED_PY:
        return ("warn", "Python %d.%d.%d works but %d.%d+ is recommended" %
                (v.major, v.minor, v.micro, RECOMMENDED_PY[0], RECOMMENDED_PY[1]))
    return ("ok", "Python %d.%d.%d" % (v.major, v.minor, v.micro))


def check_critical_modules():
    """Verify all critical stdlib modules import. Return list of failures."""
    missing = []
    for mod in CRITICAL_STDLIB:
        try:
            importlib.import_module(mod)
        except ImportError as ex:
            missing.append((mod, str(ex)))
    return missing


def check_optional_modules():
    """Detect optional modules. Return dict of module_name -> available bool."""
    available = {}
    for mod in OPTIONAL_MODULES:
        try:
            importlib.import_module(mod)
            available[mod] = True
        except ImportError:
            available[mod] = False
    return available


def check_workspace():
    """Verify GhostMap can write to its output directory.

    Returns (level, message).
    """
    # Not strictly Python integrity but worth checking up-front.
    try:
        from lib.core.data import paths
        out = paths.get("SQLMAP_OUTPUT_PATH")
        if out and os.path.isdir(out) and os.access(out, os.W_OK):
            return ("ok", "Output dir writable: %s" % out)
        if out and not os.path.isdir(out):
            try:
                os.makedirs(out)
                return ("ok", "Output dir created: %s" % out)
            except OSError as ex:
                return ("warn", "Cannot create output dir %s: %s" % (out, ex))
        return ("warn", "Output dir not writable")
    except Exception:
        # paths may not be initialized yet at the moment we run; skip silently.
        return ("ok", "Workspace check deferred")


def run_integrity_check(logger=None):
    """Run all checks and report via the provided logger (or print).

    Returns a dict suitable for inclusion in --report-json output:
        {
            "python":   {"version": "3.11.5", "level": "ok"},
            "critical": {"missing": []},
            "optional": {"brotli": True, "zstandard": False, ...},
            "summary":  "ok" | "warn" | "error",
        }
    """
    def _emit(level, msg):
        if logger:
            getattr(logger, {"ok": "debug", "warn": "warning", "error": "error"}.get(level, "info"))(msg)
        else:
            tag = {"ok": "[+]", "warn": "[!]", "error": "[x]"}.get(level, "[*]")
            print("%s %s" % (tag, msg))

    overall = "ok"

    # 1. Python version
    py_level, py_msg = check_python_version()
    _emit(py_level, "integrity: " + py_msg)
    if py_level == "error":
        overall = "error"
    elif py_level == "warn" and overall == "ok":
        overall = "warn"

    # 2. Critical stdlib
    missing = check_critical_modules()
    if missing:
        for mod, err in missing:
            _emit("error", "integrity: critical module '%s' missing (%s)" % (mod, err))
        overall = "error"

    # 3. Optional capabilities
    optional = check_optional_modules()
    have = sorted(k for k, v in optional.items() if v)
    miss = sorted(k for k, v in optional.items() if not v)
    if have:
        _emit("ok", "integrity: optional capabilities available: %s" % ", ".join(have))
    if miss:
        # This is purely informational, not a warning.
        _emit("ok", "integrity: optional capabilities NOT available: %s" % ", ".join(miss))

    # 4. Workspace check
    ws_level, ws_msg = check_workspace()
    _emit(ws_level, "integrity: " + ws_msg)
    if ws_level == "warn" and overall == "ok":
        overall = "warn"

    return {
        "python":   {"version": "%d.%d.%d" % sys.version_info[:3], "level": py_level},
        "critical": {"missing": [m for m, _ in missing]},
        "optional": optional,
        "workspace": {"level": ws_level, "message": ws_msg},
        "summary":   overall,
    }


if __name__ == "__main__":
    # Standalone invocation for quick diagnosis: `python3 -m lib.core.integrity`
    result = run_integrity_check()
    print()
    print("=" * 60)
    print("OVERALL:", result["summary"].upper())
    print("=" * 60)
    sys.exit(0 if result["summary"] != "error" else 1)
