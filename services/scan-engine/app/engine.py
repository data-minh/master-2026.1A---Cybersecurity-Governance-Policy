"""Self-written YAML vulnerability template engine (Người 2 - B1).

This is the central technical deliverable of Người 2: a from-scratch engine that
reads a Nuclei-style YAML template, issues HTTP requests, applies matchers
(status / word / regex / json) and extractors, and decides whether a target is
vulnerable. It deliberately does NOT shell out to an existing binary.

Template schema (subset of the widely-used Nuclei format):

    id: example-template
    info:
      name: Example
      severity: medium
      description: ...
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/path"
        headers:
          User-Agent: vts-scanner
        matchers-condition: and        # and | or   (default: or)
        matchers:
          - type: status
            status: [200]
          - type: word
            part: body                 # body | header | all   (default: body)
            words: ["admin"]
            condition: or              # and | or (within this matcher)
          - type: regex
            part: body
            regex: ["root:.*:0:0:"]
          - type: json
            part: body
            json: ["$.error"]          # dotted/JSONPath-lite expression must exist
        extractors:
          - type: regex
            part: body
            regex: ["version ([0-9.]+)"]
            group: 1

The engine is transport-agnostic: `HttpTemplateEngine` performs real HTTP via
httpx, but the matcher/extractor logic lives in pure functions so it is unit
testable without a network (see tests/).
"""
from __future__ import annotations

import json as jsonlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

# Bound how much of a response body a single matcher/extractor scans. Keeps
# regex cost predictable and blunts ReDoS even on a crafted large response.
MAX_SCAN_BYTES = 512 * 1024

# ---------------------------------------------------------------------------
# Response abstraction (so matchers can be tested without real HTTP)
# ---------------------------------------------------------------------------
@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)

    def part(self, name: str) -> str:
        name = (name or "body").lower()
        if name == "body":
            return self.body[:MAX_SCAN_BYTES]
        if name == "header":
            return "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        if name == "all":
            hdr = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            return f"{hdr}\n\n{self.body}"[:MAX_SCAN_BYTES]
        return self.body[:MAX_SCAN_BYTES]


# ---------------------------------------------------------------------------
# Matchers  (status / word / regex / json)
# ---------------------------------------------------------------------------
def _match_status(resp: HttpResponse, spec: dict) -> bool:
    wanted = spec.get("status", [])
    return resp.status in wanted


def _match_word(resp: HttpResponse, spec: dict) -> bool:
    words = spec.get("words", [])
    hay = resp.part(spec.get("part", "body"))
    cond = spec.get("condition", "or").lower()
    if not spec.get("case_sensitive", False):
        hay = hay.lower()
        words = [w.lower() for w in words]
    results = [w in hay for w in words]
    return all(results) if cond == "and" else any(results)


def _match_regex(resp: HttpResponse, spec: dict) -> bool:
    patterns = spec.get("regex", [])
    hay = resp.part(spec.get("part", "body"))
    cond = spec.get("condition", "or").lower()
    results = [re.search(p, hay) is not None for p in patterns]
    return all(results) if cond == "and" else any(results)


def _json_path_lite(obj: Any, expr: str) -> bool:
    """Minimal JSONPath-lite: supports $.a.b, $.a[0].b and plain a.b."""
    expr = expr.strip()
    if expr.startswith("$"):
        expr = expr[1:]
    expr = expr.lstrip(".")
    cur = obj
    token = ""
    tokens: list[str] = []
    for ch in expr:
        if ch == ".":
            if token:
                tokens.append(token); token = ""
        elif ch == "[":
            if token:
                tokens.append(token); token = ""
            token = "["
        elif ch == "]":
            tokens.append(token + "]"); token = ""
        else:
            token += ch
    if token:
        tokens.append(token)
    for tk in tokens:
        if tk.startswith("[") and tk.endswith("]"):
            idx = tk[1:-1]
            try:
                cur = cur[int(idx)]
            except (ValueError, IndexError, KeyError, TypeError):
                return False
        else:
            if isinstance(cur, dict) and tk in cur:
                cur = cur[tk]
            else:
                return False
    return True


def _match_json(resp: HttpResponse, spec: dict) -> bool:
    exprs = spec.get("json", [])
    cond = spec.get("condition", "or").lower()
    try:
        obj = jsonlib.loads(resp.part(spec.get("part", "body")))
    except (jsonlib.JSONDecodeError, TypeError):
        return False
    results = [_json_path_lite(obj, e) for e in exprs]
    return all(results) if cond == "and" else any(results)


MATCHERS = {
    "status": _match_status,
    "word": _match_word,
    "regex": _match_regex,
    "json": _match_json,
}


def apply_matchers(resp: HttpResponse, matchers: list[dict],
                   matchers_condition: str = "or") -> bool:
    if not matchers:
        return False
    outcomes = []
    for m in matchers:
        fn = MATCHERS.get(m.get("type"))
        if fn is None:
            outcomes.append(False)
            continue
        res = fn(resp, m)
        if m.get("negative"):
            res = not res
        outcomes.append(res)
    cond = (matchers_condition or "or").lower()
    return all(outcomes) if cond == "and" else any(outcomes)


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------
def apply_extractors(resp: HttpResponse, extractors: list[dict]) -> list[str]:
    out: list[str] = []
    for ex in extractors or []:
        if ex.get("type") == "regex":
            group = ex.get("group", 0)
            hay = resp.part(ex.get("part", "body"))
            for pat in ex.get("regex", []):
                for m in re.finditer(pat, hay):
                    try:
                        out.append(m.group(group))
                    except (IndexError, re.error):
                        out.append(m.group(0))
        elif ex.get("type") == "kval":  # header key extraction
            for key in ex.get("kval", []):
                if key in resp.headers:
                    out.append(resp.headers[key])
    return out


# ---------------------------------------------------------------------------
# Template evaluation (pure, no network)
# ---------------------------------------------------------------------------
@dataclass
class MatchResult:
    matched: bool
    template_id: str
    severity: str
    name: str
    extracted: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def evaluate_request(template: dict, request_spec: dict,
                     resp: HttpResponse) -> MatchResult:
    info = template.get("info", {})
    matched = apply_matchers(
        resp,
        request_spec.get("matchers", []),
        request_spec.get("matchers-condition", "or"),
    )
    extracted = apply_extractors(resp, request_spec.get("extractors", [])) if matched else []
    return MatchResult(
        matched=matched,
        template_id=template.get("id", "unknown"),
        severity=info.get("severity", "info"),
        name=info.get("name", template.get("id", "unknown")),
        extracted=extracted,
        evidence={"status": resp.status,
                  "body_snippet": resp.body[:200]} if matched else {},
    )


# ---------------------------------------------------------------------------
# Template validation (B2 safety: reject dangerous templates before storing)
# ---------------------------------------------------------------------------
DANGEROUS_KEYS = {"command", "cmd", "exec", "shell", "code", "payloads-exec"}
# Detection must stay non-destructive: only read-only HTTP methods are allowed.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_REQUEST_TYPES = {"http", "requests"}

# Heuristic for catastrophic-backtracking (ReDoS) patterns: a quantified group
# that is itself quantified, e.g. (a+)+, (a*)+, (.+)*, (ab|a)+ ... . Not perfect,
# but rejects the classic foot-guns before a user template is ever executed.
_REDOS_HINT = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")
MAX_REGEX_LEN = 512


def _check_regex_list(patterns: Any, where: str, errors: list[str]) -> None:
    if not isinstance(patterns, list):
        return
    for pat in patterns:
        if not isinstance(pat, str):
            errors.append(f"{where}: regex must be a string")
            continue
        if len(pat) > MAX_REGEX_LEN:
            errors.append(f"{where}: regex too long (>{MAX_REGEX_LEN} chars)")
        try:
            re.compile(pat)
        except re.error as exc:
            errors.append(f"{where}: invalid regex ({exc})")
            continue
        if _REDOS_HINT.search(pat):
            errors.append(f"{where}: potentially catastrophic regex (ReDoS) rejected")


def validate_template(template: dict) -> list[str]:
    """Return a list of validation errors; empty list means valid & safe."""
    errors: list[str] = []
    if not isinstance(template, dict):
        return ["template must be a mapping"]
    if not template.get("id"):
        errors.append("missing 'id'")
    info = template.get("info", {})
    if not info.get("severity"):
        errors.append("missing info.severity")
    sev = str(info.get("severity", "")).lower()
    if sev and sev not in {"info", "low", "medium", "high", "critical"}:
        errors.append(f"invalid severity: {sev}")

    reqs = template.get("requests") or template.get("http")
    if not reqs:
        errors.append("missing 'requests'/'http' section")
        return errors

    # Reject dangerous config that could enable command injection (B2 note).
    def _scan(node: Any, path: str = ""):
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k).lower() in DANGEROUS_KEYS:
                    errors.append(f"dangerous key '{k}' at {path or '/'}")
                _scan(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _scan(v, f"{path}[{i}]")

    _scan(reqs, "requests")

    for i, req in enumerate(reqs):
        if not isinstance(req, dict):
            errors.append(f"requests[{i}] must be a mapping")
            continue
        method = str(req.get("method", "GET")).upper()
        if method not in SAFE_METHODS:
            errors.append(f"requests[{i}] method '{method}' is not allowed (read-only methods only)")
        if not req.get("matchers"):
            errors.append(f"requests[{i}] has no matchers")
        for j, m in enumerate(req.get("matchers", [])):
            if m.get("type") not in MATCHERS:
                errors.append(f"requests[{i}] unknown matcher type: {m.get('type')}")
            if m.get("type") == "regex":
                _check_regex_list(m.get("regex"), f"requests[{i}].matchers[{j}]", errors)
        for j, ex in enumerate(req.get("extractors", []) or []):
            if ex.get("type") == "regex":
                _check_regex_list(ex.get("regex"), f"requests[{i}].extractors[{j}]", errors)
    return errors
