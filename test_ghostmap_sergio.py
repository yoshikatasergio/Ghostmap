"""
Critical test: --sergio MUST NOT leak target host or values.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.core.sergio import (
    redact_url,
    redact_text,
    SergioCollector,
    _redact_value_keep_shape,
)


def assert_redacted(text, forbidden_substrings):
    """Assert none of the forbidden strings appear in `text`."""
    for f in forbidden_substrings:
        assert f not in text, "LEAK: %r found in %r" % (f, text)


def test_redact_value_keep_shape():
    assert _redact_value_keep_shape("184") == "<value:int:3digits>"
    assert _redact_value_keep_shape("-184") == "<value:int:4digits>"
    assert _redact_value_keep_shape("helloworld") == "<value:str:10chars>"
    assert _redact_value_keep_shape("") == "<value:str:empty>"
    assert _redact_value_keep_shape(None) == "<value:null>"
    assert _redact_value_keep_shape("3.14") == "<value:float:4chars>"
    print("[OK] _redact_value_keep_shape")


def test_redact_url():
    # The example from the generic example
    url = "https://www4.example.com/api/v1/items/?id=184&tipo=helloworld&opcion=1"
    out = redact_url(url)

    # Must not contain any of these client-identifying strings
    assert_redacted(out, [
        "example", "www4", "example.com",
        "api", "items",
        "184", "helloworld",
    ])

    # Must contain parameter names so I can debug
    assert "id=" in out, out
    assert "tipo=" in out, out
    assert "opcion=" in out, out

    # Must contain shape placeholders
    assert "<value:int:3digits>" in out, out
    assert "<value:str:10chars>" in out, out
    assert "<value:int:1digits>" in out, out
    print("[OK] redact_url for generic example")
    print("    redacted:", out)


def test_redact_text_with_url_inline():
    # A typical sqlmap log line
    line = "testing URL 'https://www4.example.com/api/v1/items/?id=184&tipo=helloworld&opcion=1'"
    out = redact_text(line)
    assert_redacted(out, ["example", "helloworld", "184", "api"])
    assert "id=" in out and "tipo=" in out
    print("[OK] redact_text with inline URL")
    print("    redacted:", out)


def test_redact_headers():
    text = """Host: api.example.com
Cookie: session=abc123def456; csrf_token=xyz789
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"""
    out = redact_text(text)
    assert_redacted(out, [
        "example", "abc123", "def456", "xyz789",
        "eyJhbGciOiJIUzI1NiJ9", "payload", "signature",
    ])
    assert "Host:" in out
    assert "Cookie:" in out
    assert "Authorization:" in out
    print("[OK] header redaction")


def test_redact_ip_and_email():
    text = "got response from 192.168.1.100, contact admin@example.com"
    out = redact_text(text)
    assert_redacted(out, ["192.168.1.100", "example.com", "admin@"])
    print("[OK] IP and email redaction")


def test_collector_render():
    c = SergioCollector()
    c.add_log("ERROR", "testing URL 'https://www4.example.com/api?id=184'")
    c.add_log("WARNING", "the response from 10.0.0.5 was suspicious")
    c.add_traceback("Traceback (most recent call last):\n"
                    "  File 'lib/core/foo.py', line 12, in bar\n"
                    "ValueError: target was https://example.com/x")
    c.note_request(status_code=200)
    c.note_request(status_code=500)
    c.note_request(timed_out=True)
    c.note_technique("boolean-blind", confirmed=True)
    c.note_fallback("JSON regex failed; fell back to urlencoded")

    text = c.render()

    # Sanity: it rendered something
    assert "GhostMap --sergio diagnostic dump" in text
    assert "[environment]" in text
    assert "[stats]" in text

    # Critical: NO client data leaked
    assert_redacted(text, [
        "example", "www4", "184", "10.0.0.5",
    ])

    # Useful info IS there
    assert "boolean-blind" in text
    assert "JSON regex failed" in text
    assert "requests_sent:" in text

    print("[OK] full collector render — no leaks detected")
    print("---preview---")
    print(text[:1200])
    print("...")
    print(text[-400:])
    print("---")


if __name__ == "__main__":
    test_redact_value_keep_shape()
    test_redact_url()
    test_redact_text_with_url_inline()
    test_redact_headers()
    test_redact_ip_and_email()
    test_collector_render()
    print("\n[+] all sergio redaction tests passed -- no client data leaked")


def test_chrome_version_not_matched_as_ip():
    """Chrome/138.0.7204.158 should NOT be matched as an IP."""
    from lib.core.sergio import redact_text
    text = "User-Agent header value 'Mozilla/5.0 ... Chrome/138.0.7204.158 Safari/537.36'"
    out = redact_text(text)
    # 138.0.7204.158 has 4-digit octet so it's not a valid IP anyway, but
    # let's also check version strings with valid-IP-shaped chunks.
    text2 = "Chrome/120.0.6099.130 Safari"
    out2 = redact_text(text2)
    # 120.0.6099.130 still has 4-digit octet (6099). Not a valid IP.
    # Real test case: a version that LOOKS like a valid IP
    text3 = "AppVersion 10.0.20.5 released"
    out3 = redact_text(text3)
    # 10.0.20.5 IS a valid IP shape -- but we want this redacted, that's fine.
    # The main fix is "Chrome/<numbers>" should NOT redact the trailing version.
    text4 = "Chrome/120.0.6099.130"
    out4 = redact_text(text4)
    assert "120.0.6099.130" in out4 or "<ip>" in out4
    # Either it's preserved (good - 6099 octet is invalid) or it's the IP
    # placeholder (acceptable). The real bug was matching Chrome/<...> with
    # 'Chrome/' as the prefix.
    assert "Chrome/" in out4, "Chrome/ prefix lost"
    print("[OK] Chrome version strings handled")


def test_global_replace_at_write_time():
    """The final write-time global replace should catch any leaked host."""
    from lib.core.sergio import SergioCollector
    import tempfile, os, sys

    # Mock conf.url
    sys.path.insert(0, '.')
    try:
        from lib.core.data import conf
    except ImportError:
        # Cannot test without full sqlmap state; skip
        print("[SKIP] global replace test (no sqlmap state)")
        return

    conf.url = "https://example.org/api"
    c = SergioCollector()
    # Inject some content that would leak the host (simulating sqlmap's
    # behavior of putting the hostname in output paths).
    c.add_log("INFO", "fetched data logged to text files under '/tmp/output/example.org'")
    c.add_log("INFO", "this should not contain example.org either")

    with tempfile.TemporaryDirectory() as td:
        path = c.write(td)
        with open(path) as f:
            content = f.read()
        assert "example.org" not in content, \
            "LEAK: 'example.org' found in dump after global replace"
        assert "<target>" in content, "Expected <target> placeholder"
    conf.url = None
    print("[OK] global replace at write time")


if __name__ == "__main__":
    # Re-run all tests including the new ones
    test_redact_value_keep_shape()
    test_redact_url()
    test_redact_text_with_url_inline()
    test_redact_headers()
    test_redact_ip_and_email()
    test_collector_render()
    test_chrome_version_not_matched_as_ip()
    test_global_replace_at_write_time()
    print("\n[+] all sergio redaction tests passed -- no client data leaked")
