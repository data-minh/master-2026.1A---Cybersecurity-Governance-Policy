"""Unit tests for the self-written template engine (Người 2 - B1 deliverable).

Covers each matcher type (status, word, regex, json), extractors, matcher
conditions (and/or), negative matchers, and template validation/safety.
Run: pytest services/scan-engine/tests -q
"""
import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from engine import (  # noqa: E402
    HttpResponse,
    apply_matchers,
    apply_extractors,
    evaluate_request,
    validate_template,
)


# --------------------------- status matcher -------------------------------
def test_status_matcher_hit():
    resp = HttpResponse(status=200, body="")
    assert apply_matchers(resp, [{"type": "status", "status": [200, 301]}])


def test_status_matcher_miss():
    resp = HttpResponse(status=404, body="")
    assert not apply_matchers(resp, [{"type": "status", "status": [200]}])


# --------------------------- word matcher ---------------------------------
def test_word_matcher_or():
    resp = HttpResponse(status=200, body="welcome admin panel")
    assert apply_matchers(resp, [{"type": "word", "words": ["admin", "root"],
                                  "condition": "or"}])


def test_word_matcher_and_fails():
    resp = HttpResponse(status=200, body="welcome admin panel")
    assert not apply_matchers(resp, [{"type": "word", "words": ["admin", "root"],
                                      "condition": "and"}])


def test_word_matcher_header_part():
    resp = HttpResponse(status=200, body="", headers={"Server": "nginx/1.25"})
    assert apply_matchers(resp, [{"type": "word", "part": "header",
                                  "words": ["nginx"]}])


# --------------------------- regex matcher --------------------------------
def test_regex_matcher():
    resp = HttpResponse(status=200, body="root:x:0:0:root:/root:/bin/bash")
    assert apply_matchers(resp, [{"type": "regex", "regex": ["root:.*:0:0:"]}])


def test_regex_matcher_no_match():
    resp = HttpResponse(status=200, body="hello world")
    assert not apply_matchers(resp, [{"type": "regex", "regex": ["\\d{4}-secret"]}])


# --------------------------- json matcher ---------------------------------
def test_json_matcher_path_exists():
    resp = HttpResponse(status=200, body='{"status":"UP","details":{"db":"ok"}}')
    assert apply_matchers(resp, [{"type": "json", "json": ["$.status"]}])
    assert apply_matchers(resp, [{"type": "json", "json": ["$.details.db"]}])


def test_json_matcher_path_missing():
    resp = HttpResponse(status=200, body='{"status":"UP"}')
    assert not apply_matchers(resp, [{"type": "json", "json": ["$.secret.key"]}])


def test_json_matcher_invalid_body():
    resp = HttpResponse(status=200, body="not-json")
    assert not apply_matchers(resp, [{"type": "json", "json": ["$.x"]}])


# --------------------------- matchers-condition ---------------------------
def test_matchers_condition_and():
    resp = HttpResponse(status=200, body="PHP Version 8.1")
    matchers = [{"type": "status", "status": [200]},
                {"type": "word", "words": ["PHP Version"]}]
    assert apply_matchers(resp, matchers, "and")


def test_matchers_condition_and_one_fails():
    resp = HttpResponse(status=500, body="PHP Version 8.1")
    matchers = [{"type": "status", "status": [200]},
                {"type": "word", "words": ["PHP Version"]}]
    assert not apply_matchers(resp, matchers, "and")


def test_negative_matcher():
    resp = HttpResponse(status=200, body="all good")
    assert apply_matchers(resp, [{"type": "word", "words": ["error"],
                                  "negative": True}])


# --------------------------- extractors -----------------------------------
def test_extractor_regex_group():
    resp = HttpResponse(status=200, body="PHP Version 8.1.2 built")
    out = apply_extractors(resp, [{"type": "regex",
                                   "regex": ["PHP Version ([0-9.]+)"], "group": 1}])
    assert out == ["8.1.2"]


def test_extractor_kval_header():
    resp = HttpResponse(status=200, body="", headers={"Server": "nginx"})
    out = apply_extractors(resp, [{"type": "kval", "kval": ["Server"]}])
    assert out == ["nginx"]


# --------------------------- evaluate_request -----------------------------
def test_evaluate_request_full():
    tpl = {"id": "t1", "info": {"name": "T1", "severity": "high"}}
    req = {"matchers-condition": "and",
           "matchers": [{"type": "status", "status": [200]},
                        {"type": "word", "words": ["secret"]}],
           "extractors": [{"type": "regex", "regex": ["secret=(\\w+)"], "group": 1}]}
    resp = HttpResponse(status=200, body="secret=abc123")
    res = evaluate_request(tpl, req, resp)
    assert res.matched is True
    assert res.severity == "high"
    assert res.extracted == ["abc123"]


# --------------------------- validation / safety --------------------------
def test_validate_good_template():
    tpl = yaml.safe_load("""
id: good
info: {name: Good, severity: low}
requests:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
""")
    assert validate_template(tpl) == []


def test_validate_rejects_dangerous_command_key():
    tpl = yaml.safe_load("""
id: evil
info: {name: Evil, severity: high}
requests:
  - method: GET
    command: ["rm -rf /"]
    matchers:
      - type: status
        status: [200]
""")
    errors = validate_template(tpl)
    assert any("dangerous key" in e for e in errors)


def test_validate_rejects_missing_fields():
    assert "missing 'id'" in validate_template({"info": {}, "requests": []})


def test_validate_rejects_unknown_matcher():
    tpl = {"id": "x", "info": {"severity": "low"},
           "requests": [{"matchers": [{"type": "bogus"}]}]}
    errors = validate_template(tpl)
    assert any("unknown matcher" in e for e in errors)


def test_validate_rejects_redos_regex():
    tpl = {"id": "redos", "info": {"severity": "low"},
           "requests": [{"matchers": [{"type": "regex", "regex": ["(a+)+$"]}]}]}
    errors = validate_template(tpl)
    assert any("ReDoS" in e for e in errors)


def test_validate_rejects_invalid_regex():
    tpl = {"id": "badre", "info": {"severity": "low"},
           "requests": [{"matchers": [{"type": "regex", "regex": ["("]}]}]}
    errors = validate_template(tpl)
    assert any("invalid regex" in e for e in errors)


def test_validate_rejects_redos_in_extractor():
    tpl = {"id": "redos2", "info": {"severity": "low"},
           "requests": [{"matchers": [{"type": "status", "status": [200]}],
                         "extractors": [{"type": "regex", "regex": ["(x*)*"]}]}]}
    errors = validate_template(tpl)
    assert any("ReDoS" in e for e in errors)


def test_validate_rejects_state_changing_http_method():
    for method in ("DELETE", "post", "PUT", "PATCH"):
        tpl = {"id": "m", "info": {"severity": "low"},
               "requests": [{"method": method,
                             "matchers": [{"type": "status", "status": [200]}]}]}
        assert any("method" in e for e in validate_template(tpl)), method
    ok = {"id": "m", "info": {"severity": "low"},
          "requests": [{"method": "head",
                        "matchers": [{"type": "status", "status": [200]}]}]}
    assert validate_template(ok) == []


def test_part_is_bounded():
    from engine import MAX_SCAN_BYTES
    resp = HttpResponse(status=200, body="A" * (MAX_SCAN_BYTES + 100))
    assert len(resp.part("body")) == MAX_SCAN_BYTES


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
