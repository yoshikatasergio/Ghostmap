#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

GhostMap / Yoshi Edition addition
---------------------------------
Robust JSON body parser for sqlmap.

Purpose
-------
The stock sqlmap JSON detection in lib/core/target.py is regex-based.
It works for most common JSON bodies, but has gaps:

1. It can miss injection points in deeply-nested objects when the
   user wants to address them by path (e.g. -p '$.user.profile.email').
2. It cannot enumerate injection points up-front so the operator can
   see what is going to be tested before any request is sent.
3. It accepts the body as JSON-or-not based on a single regex; a body
   that the regex misses (rare but possible: trailing garbage,
   non-standard whitespace, BOM) silently falls through to urlencoded
   parsing and only one "parameter" gets tested.

This module is a *complement* to the existing regex flow, not a
replacement. The original regex path is left intact in target.py.
We only kick in when:

  - The regex did not match, AND
  - json.loads() succeeds on the body

In that case we treat it as JSON, mark all leaf values as injectable
using sqlmap's standard custom injection marker, and tell the user
what we found.

We also expose enumerate_injection_points() for use elsewhere
(printing a summary, --report-json, etc.).

This module performs no I/O and makes no network calls. It only
parses strings the operator already passed in via --data.
"""

from __future__ import print_function

import json
import re


# Maximum depth we will descend into a JSON document. Pathological
# inputs (deeply nested attacker-crafted bodies in fuzzing scenarios)
# can blow the stack; sqlmap is read-only here but still defensive.
MAX_JSON_DEPTH = 64

# Types that we treat as "leaf" injection points. Booleans and null
# are technically leaves in JSON but not interesting injection targets
# in most SQL contexts -- they round-trip through ORM layers as
# typed values, not strings. We still mark them but flag them as
# low-priority so the user can skip with -p.
LEAF_PRIMITIVE_TYPES = (str, int, float, bool, type(None))


def is_probably_json(data):
    """Return True if `data` looks like a JSON document.

    Uses a two-pass strategy:
      1. Fast structural check: starts with '{' or '[' (after whitespace
         and BOM stripping)
      2. Attempt json.loads() to confirm

    Returns True only if both pass. This is more permissive than the
    stock regex (which requires at least one "key": value pair) and
    catches edge cases like '[]', '{}', and pretty-printed bodies.
    """
    if not isinstance(data, str) or not data:
        return False

    # Strip UTF-8 BOM if present
    s = data.lstrip("\ufeff").lstrip()
    if not s:
        return False

    if s[0] not in ("{", "["):
        return False

    try:
        # Strip BOM before passing to json.loads as some Python versions
        # / json libraries reject leading BOM.
        json.loads(data.lstrip("\ufeff"))
        return True
    except (ValueError, TypeError):
        return False


def _walk(node, path, out, depth=0):
    """Recursively walk a parsed JSON tree, recording leaf positions.

    `path` is a list of segments. Object keys are strings, array
    indices are integers. We keep them as a list so we can format
    them either as JSONPath ($.a.b[0]) or as JSON Pointer (/a/b/0)
    later, depending on what the caller wants.
    """
    if depth > MAX_JSON_DEPTH:
        return

    if isinstance(node, dict):
        for key, value in node.items():
            _walk(value, path + [str(key)], out, depth + 1)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            _walk(value, path + [idx], out, depth + 1)
    elif isinstance(node, LEAF_PRIMITIVE_TYPES):
        out.append((list(path), node, _classify(node)))


def _classify(value):
    """Return a short human-readable type label for a leaf value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        # IMPORTANT: bool is a subclass of int in Python. Check before int.
        return "bool"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _format_jsonpath(path):
    """Format a path list as a JSONPath-ish string ($.a.b[0])."""
    parts = ["$"]
    for seg in path:
        if isinstance(seg, int):
            parts.append("[%d]" % seg)
        else:
            # Quote keys with characters that aren't safe identifiers
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", seg):
                parts.append("." + seg)
            else:
                parts.append("['%s']" % seg.replace("'", "\\'"))
    return "".join(parts)


def enumerate_injection_points(data):
    """Parse `data` as JSON and return a list of injection point descriptors.

    Each descriptor is a dict:
        {
            "path":     list,          # raw path segments
            "jsonpath": str,           # "$.user.email"
            "type":     str,           # "string", "integer", ...
            "value":    primitive,     # the original leaf value
            "depth":    int,           # nesting depth (1 = top level)
        }

    Returns an empty list if data is not valid JSON.
    """
    if not is_probably_json(data):
        return []

    try:
        tree = json.loads(data.lstrip("\ufeff"))
    except (ValueError, TypeError):
        return []

    leaves = []
    _walk(tree, [], leaves)

    points = []
    for path, value, type_label in leaves:
        points.append({
            "path": path,
            "jsonpath": _format_jsonpath(path),
            "type": type_label,
            "value": value,
            "depth": len(path),
        })
    return points


def format_summary(points, max_value_len=40):
    """Format an injection-point list for human display.

    Returns a multi-line string. Used by target.py to show the user
    what will be tested before any HTTP request is sent.
    """
    if not points:
        return "  (no injection points detected)"

    lines = []
    width = len(str(len(points)))

    for i, p in enumerate(points, 1):
        val = repr(p["value"])
        if len(val) > max_value_len:
            val = val[:max_value_len - 3] + "..."

        depth_marker = ""
        if p["depth"] > 1:
            depth_marker = "  (depth=%d)" % p["depth"]

        lines.append("    [%s] %-30s %-8s = %s%s" % (
            str(i).rjust(width),
            p["jsonpath"],
            p["type"],
            val,
            depth_marker,
        ))
    return "\n".join(lines)


def path_matches_test_parameter(jsonpath, test_parameter):
    """Decide whether a discovered injection point matches a -p value.

    sqlmap's -p flag accepts simple parameter names. We extend the
    matching to support:

      - bare key: 'username' matches '$.username' and '$.user.username'
        (last segment match)
      - dotted path: 'user.email' matches '$.user.email'
      - jsonpath: '$.user.email' matches itself
      - JSON Pointer: '/user/email' matches '$.user.email'

    Returns True if the user's -p value should select this point.
    """
    if not test_parameter:
        return True

    tp = test_parameter.strip()

    # Exact JSONPath match
    if tp == jsonpath:
        return True

    # JSON Pointer (RFC 6901) - convert to dotted form
    if tp.startswith("/"):
        dotted = tp[1:].replace("/", ".")
        if jsonpath == "$." + dotted or jsonpath.endswith("." + dotted):
            return True

    # Dotted form
    if "." in tp:
        if jsonpath == "$." + tp or jsonpath.endswith("." + tp):
            return True

    # Bare key - match last segment
    last_segment = jsonpath.rsplit(".", 1)[-1].rstrip("]")
    last_segment = re.sub(r"\[\d+\]$", "", last_segment)
    if last_segment == tp:
        return True

    return False
