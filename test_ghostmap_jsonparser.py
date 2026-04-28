"""
Test the new jsonparser module against realistic JSON bodies seen
in real APIs. We assert behavior; we don't just print.
"""
import sys
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.core.jsonparser import (
    is_probably_json,
    enumerate_injection_points,
    format_summary,
    path_matches_test_parameter,
)


def test_is_probably_json():
    assert is_probably_json('{"a":1}')
    assert is_probably_json('[1,2,3]')
    assert is_probably_json('  {"a": 1}  ')
    assert is_probably_json('{}')
    assert is_probably_json('[]')
    assert is_probably_json('\ufeff{"a":1}')        # UTF-8 BOM
    assert is_probably_json('{\n  "a": "b"\n}')     # pretty-printed
    assert not is_probably_json('id=1&name=foo')    # urlencoded
    assert not is_probably_json('')
    assert not is_probably_json(None)
    assert not is_probably_json('{"a":1,}')         # trailing comma -> invalid JSON
    assert not is_probably_json('not json at all')
    print("[OK] is_probably_json")


def test_enumerate_flat():
    pts = enumerate_injection_points('{"username":"admin","password":"x"}')
    assert len(pts) == 2
    paths = sorted(p["jsonpath"] for p in pts)
    assert paths == ["$.password", "$.username"]
    print("[OK] enumerate flat")


def test_enumerate_nested():
    body = '{"user":{"name":"admin","creds":{"pass":"x","token":"y"}}}'
    pts = enumerate_injection_points(body)
    paths = sorted(p["jsonpath"] for p in pts)
    assert paths == ["$.user.creds.pass", "$.user.creds.token", "$.user.name"]
    # Depth should reflect nesting
    by_path = {p["jsonpath"]: p for p in pts}
    assert by_path["$.user.name"]["depth"] == 2
    assert by_path["$.user.creds.pass"]["depth"] == 3
    print("[OK] enumerate nested")


def test_enumerate_with_arrays():
    body = '{"users":[{"name":"a"},{"name":"b","tags":["x","y"]}]}'
    pts = enumerate_injection_points(body)
    paths = sorted(p["jsonpath"] for p in pts)
    expected = sorted([
        "$.users[0].name",
        "$.users[1].name",
        "$.users[1].tags[0]",
        "$.users[1].tags[1]",
    ])
    assert paths == expected
    print("[OK] enumerate arrays")


def test_types_classified():
    body = '{"s":"text","n":42,"f":3.14,"b":true,"z":null,"b2":false}'
    pts = enumerate_injection_points(body)
    type_map = {p["jsonpath"]: p["type"] for p in pts}
    assert type_map["$.s"] == "string"
    assert type_map["$.n"] == "integer"
    assert type_map["$.f"] == "number"
    assert type_map["$.b"] == "bool", "got %r" % type_map["$.b"]
    assert type_map["$.b2"] == "bool"
    assert type_map["$.z"] == "null"
    print("[OK] type classification (bool/int distinction)")


def test_path_matching():
    # Bare key matches by last segment
    assert path_matches_test_parameter("$.username", "username")
    assert path_matches_test_parameter("$.user.email", "email")

    # Dotted path matches exact tail
    assert path_matches_test_parameter("$.user.email", "user.email")
    assert not path_matches_test_parameter("$.profile.name", "user.name")

    # JSONPath exact
    assert path_matches_test_parameter("$.user.email", "$.user.email")

    # JSON Pointer
    assert path_matches_test_parameter("$.user.email", "/user/email")

    # No filter -> all match
    assert path_matches_test_parameter("$.anything", "")
    assert path_matches_test_parameter("$.anything", None)

    print("[OK] path_matches_test_parameter")


def test_format_summary():
    body = '{"username":"admin","password":"hunter2","metadata":{"ip":"1.2.3.4"}}'
    pts = enumerate_injection_points(body)
    out = format_summary(pts)
    # Must contain all three paths
    assert "$.username" in out
    assert "$.password" in out
    assert "$.metadata.ip" in out
    # depth>1 marker for nested
    assert "depth=2" in out
    print("[OK] format_summary")
    print("---preview---")
    print(out)
    print("---")


def test_keys_with_special_chars():
    body = '{"weird key with space": "x", "normal": "y"}'
    pts = enumerate_injection_points(body)
    paths = sorted(p["jsonpath"] for p in pts)
    # Special-char key should be quoted
    assert any("['weird key with space']" in p for p in paths), paths
    assert any(".normal" in p for p in paths), paths
    print("[OK] special-character keys")


def test_max_depth_safety():
    # Build a deeply-nested object to ensure we don't blow the stack
    deep = '"x"'
    for _ in range(200):
        deep = '{"a":' + deep + '}'
    pts = enumerate_injection_points(deep)
    # We cap at MAX_JSON_DEPTH so we should get fewer than 200, not blow up
    assert len(pts) <= 1   # only one leaf, but it may be cut off
    print("[OK] max depth safety (no stack blow-up)")


def test_invalid_json_returns_empty():
    assert enumerate_injection_points('') == []
    assert enumerate_injection_points('not json') == []
    assert enumerate_injection_points('{') == []
    print("[OK] invalid input safe")


if __name__ == "__main__":
    test_is_probably_json()
    test_enumerate_flat()
    test_enumerate_nested()
    test_enumerate_with_arrays()
    test_types_classified()
    test_path_matching()
    test_format_summary()
    test_keys_with_special_chars()
    test_max_depth_safety()
    test_invalid_json_returns_empty()
    print("\n[+] all jsonparser tests passed")
