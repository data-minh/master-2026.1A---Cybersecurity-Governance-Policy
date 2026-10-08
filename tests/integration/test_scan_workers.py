import asyncio
import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from vts_common.lifecycle import LifecycleEnvelopeV1

ROOT = Path(__file__).parents[2]


def _load_package(package, relative):
    path = ROOT / relative
    parent = package.rsplit(".", 1)[0]
    pkg = types.ModuleType(parent)
    pkg.__path__ = [str(path.parent)]
    sys.modules[parent] = pkg
    spec = importlib.util.spec_from_file_location(package, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[package] = module
    spec.loader.exec_module(module)
    return module


engine = _load_package("test_scan_engine_app.main", "services/scan-engine/app/main.py")
specialized = _load_package("test_scan_specialized_app.main", "services/scan-specialized/app/main.py")


class Context:
    def __init__(self):
        self.events = []

    async def publish_result(self, topic, data):
        self.events.append((topic, data))
        return "1-0"


def _command(work_type, url="http://vuln-target/"):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "work.command",
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": "orchestrator",
            "attempt": 1,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "work_type": work_type,
                "input": {"url": url, "class": "page"},
                "timeout_seconds": 120,
                "max_attempts": 3,
                "dispatch_not_before": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


class AllowedScope:
    async def permits(self, host):
        return True


class DeniedScope:
    async def permits(self, host):
        return False


def test_out_of_scope_url_completes_with_zero_instead_of_failing(monkeypatch):
    called = []

    async def operation(url):
        called.append(url)
        return []

    for module, name, work_type in (
        (engine, "template_scan_operation", "scan.template_url"),
        (specialized, "specialized_scan_operation", "scan.specialized_url"),
    ):
        command = _command(work_type, "http://outside.example.org/")
        context = Context()
        monkeypatch.setattr(module, "ScopeClient", lambda: DeniedScope())
        monkeypatch.setattr(module, name, operation)
        result = asyncio.run(getattr(module, "handle_template_url" if module is engine else "handle_specialized_url")(context, command))
        assert result.result_count == 0
        assert result.outcome == {"skipped": "out_of_scope"}
        assert context.events == []
    assert called == []


def test_template_handler_awaits_operation_and_publishes_deterministic_ids(monkeypatch):
    command = _command("scan.template_url")
    context = Context()

    async def operation(url):
        await asyncio.sleep(0.02)
        return [{"url": url, "template_id": "env", "name": "Env", "severity": "high", "evidence": {}}]

    monkeypatch.setattr(engine, "ScopeClient", lambda: AllowedScope())
    monkeypatch.setattr(engine, "template_scan_operation", operation)
    result = asyncio.run(engine.handle_template_url(context, command))
    assert result.result_count == 1
    assert engine.EXECUTOR.in_flight == 0
    assert context.events[0][0] == "vuln.detected"
    assert context.events[0][1]["result_id"].startswith("sha256:")
    assert context.events[0][1]["finding_id"].startswith("sha256:")


def test_template_no_match_is_completed_zero(monkeypatch):
    command = _command("scan.template_url")
    context = Context()
    monkeypatch.setattr(engine, "ScopeClient", lambda: AllowedScope())
    monkeypatch.setattr(engine, "template_scan_operation", lambda url: asyncio.sleep(0, result=[]))
    result = asyncio.run(engine.handle_template_url(context, command))
    assert result.result_count == 0
    assert context.events == []


def test_specialized_handler_runs_page_probes_and_awaits(monkeypatch):
    command = _command("scan.specialized_url")
    context = Context()
    monkeypatch.setattr(specialized, "ScopeClient", lambda: AllowedScope())
    monkeypatch.setattr(specialized, "specialized_scan_operation", lambda url: asyncio.sleep(0.02, result=[{"url": url, "template_id": "specialized-xss", "name": "XSS", "severity": "high", "evidence": {}}]))
    result = asyncio.run(specialized.handle_specialized_url(context, command))
    assert result.result_count == 1
    assert specialized.EXECUTOR.in_flight == 0
    assert context.events[0][1]["finding_id"].startswith("sha256:")


def test_canonical_duplicate_url_has_same_finding_identity():
    scan_id = str(uuid4())
    first = engine.finding_identity(scan_id, "HTTP://VULN-TARGET:80", "env", "default")
    second = engine.finding_identity(scan_id, "http://vuln-target/", "env", "default")
    assert first == second


# --------------------------------------------------- user template management
from fastapi.testclient import TestClient  # noqa: E402

from vts_common.auth import create_token  # noqa: E402

VALID_TEMPLATE = """id: user-demo
info: {name: Demo, severity: low}
requests:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
"""


class FakeTemplateStore:
    def __init__(self):
        self.items = {}

    async def save(self, template_id, body):
        self.items[template_id] = body

    async def delete(self, template_id):
        return self.items.pop(template_id, None) is not None

    async def all(self):
        return dict(self.items)


def _as(role):
    return {"Authorization": f"Bearer {create_token(role, role)}"}


def test_only_admin_creates_or_deletes_templates_and_they_are_stored(monkeypatch):
    store = FakeTemplateStore()
    published = []

    async def publish(event, **kwargs):
        published.append(event.event)
        return "1-0"

    monkeypatch.setattr(specialized, "TEMPLATE_STORE", store)
    monkeypatch.setattr(specialized.BUS, "publish", publish)
    client = TestClient(specialized.app)  # no lifespan: no Redis needed

    denied = client.post("/templates", json={"yaml_body": VALID_TEMPLATE}, headers=_as("operator"))
    assert denied.status_code == 403 and store.items == {}

    created = client.post("/templates", json={"yaml_body": VALID_TEMPLATE}, headers=_as("admin"))
    assert created.status_code == 201 and list(store.items) == ["user-demo"]

    listing = client.get("/templates", headers=_as("operator")).json()["items"]
    assert [item["id"] for item in listing] == ["user-demo"]
    assert client.get("/templates/user-demo", headers=_as("operator")).status_code == 200
    assert client.post("/templates/validate", json={"yaml_body": VALID_TEMPLATE}, headers=_as("operator")).json()["valid"] is True

    assert client.delete("/templates/user-demo", headers=_as("operator")).status_code == 403
    assert list(store.items) == ["user-demo"]
    assert client.delete("/templates/user-demo", headers=_as("admin")).status_code == 200
    assert store.items == {}
    assert published == ["template.registered", "template.deleted"]


def test_invalid_template_is_rejected_before_storing(monkeypatch):
    store = FakeTemplateStore()
    monkeypatch.setattr(specialized, "TEMPLATE_STORE", store)
    client = TestClient(specialized.app)
    evil = "id: evil\ninfo: {severity: high}\nrequests:\n  - method: GET\n    command: ['x']\n    matchers: [{type: status, status: [200]}]\n"
    response = client.post("/templates", json={"yaml_body": evil}, headers=_as("admin"))
    assert response.status_code == 422 and store.items == {}


def test_engine_reconciles_user_templates_without_touching_file_templates():
    engine.TEMPLATES.clear()
    engine._USER_TEMPLATE_IDS.clear()
    engine.TEMPLATES["builtin"] = {"id": "builtin"}

    engine.reconcile_user_templates({"user-demo": VALID_TEMPLATE, "bad": "id: bad"})
    assert "user-demo" in engine.TEMPLATES and "bad" not in engine.TEMPLATES

    engine.reconcile_user_templates({})
    assert "user-demo" not in engine.TEMPLATES
    assert "builtin" in engine.TEMPLATES
