import asyncio
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from vts_common.lifecycle import LifecycleEnvelopeV1

ROOT = Path(__file__).parents[2]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


subdomain = _load("test_recon_subdomain_main", "services/recon-subdomain/app/main.py")
httpprobe = _load("test_recon_httpprobe_main", "services/recon-httpprobe/app/main.py")
portfuzz = _load("test_recon_portfuzz_main", "services/recon-portfuzz/app/main.py")


class Context:
    def __init__(self, command):
        self.command = command
        self.results = []
        self.progress_events = []

    async def publish_result(self, topic, data):
        self.results.append((topic, data, self.command.work_id, self.command.attempt))
        return f"{len(self.results)}-0"

    async def progress(self, sequence, percent, message, counters):
        self.progress_events.append((sequence, message))
        return "1-0"


def _command(work_type, input_data, producer="orchestrator"):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "work.command",
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": producer,
            "attempt": 1,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "work_type": work_type,
                "input": input_data,
                "timeout_seconds": 60,
                "max_attempts": 3,
                "dispatch_not_before": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


class AllowedScope:
    async def check(self, target):
        return {"allowed": True}

    async def is_allowed(self, target):
        return True

    async def permits(self, target):
        return True


class VulnTargetOnlyScope(AllowedScope):
    async def permits(self, target):
        return target == "vuln-target"


def test_http_probe_drops_out_of_scope_links_and_redirect_targets(monkeypatch):
    command = _command("recon.http_probe_and_harvest", {"host": "vuln-target"})
    context = Context(command)
    monkeypatch.setattr(httpprobe, "ScopeClient", lambda *a, **k: VulnTargetOnlyScope())
    monkeypatch.setattr(httpprobe, "_probe", lambda host, scope=None: asyncio.sleep(0, result={"host": host, "url": "http://vuln-target/", "status": 200}))
    monkeypatch.setattr(
        httpprobe,
        "_crawl_links",
        lambda url, scope=None: asyncio.sleep(0, result=["http://vuln-target/page", "https://facebook.com/share", "http://cdn.other.net/x"]),
    )
    monkeypatch.setattr(httpprobe, "RECON_EXTERNAL_SOURCES_ENABLED", False)
    result = asyncio.run(httpprobe.handle_http_probe_and_harvest(context, command))
    urls = [data["url"] for topic, data, *_ in context.results]
    assert urls == ["http://vuln-target/", "http://vuln-target/page"]
    assert result.result_count == 2

    redirected = Context(command)
    monkeypatch.setattr(httpprobe, "_probe", lambda host, scope=None: asyncio.sleep(0, result={"host": host, "url": "https://www.outside.example/", "status": 200}))
    result = asyncio.run(httpprobe.handle_http_probe_and_harvest(redirected, command))
    assert result.result_count == 0
    assert redirected.results == []


def test_recon_bootstrap_disables_external_sources_and_correlates_results(monkeypatch):
    command = _command("recon.bootstrap", {"target": "vuln-target", "mode": "recon-passive"})
    context = Context(command)
    external_calls = 0

    async def crt(_target):
        nonlocal external_calls
        external_calls += 1
        return set()

    async def resolve(host):
        return ["172.20.0.9"] if host == "vuln-target" else []

    async def osint(target):
        return {"domain": target, "emails": [], "title": "Vulnerable Target"}

    monkeypatch.setattr(subdomain, "ScopeClient", lambda *a, **k: AllowedScope())
    monkeypatch.setattr(subdomain, "_crtsh", crt)
    monkeypatch.setattr(subdomain, "_resolve", resolve)
    monkeypatch.setattr(subdomain, "_osint", osint)
    monkeypatch.setattr(subdomain, "RECON_EXTERNAL_SOURCES_ENABLED", False)

    result = asyncio.run(subdomain.handle_recon_bootstrap(context, command))
    assert result.result_count == len(context.results)
    assert external_calls == 0
    assert {topic for topic, *_ in context.results} == {"asset.subdomain.discovered", "asset.osint.collected"}
    assert all(data["result_id"].startswith("sha256:") for _, data, *_ in context.results)
    assert all(work_id == command.work_id and attempt == 1 for _, _, work_id, attempt in context.results)


def test_http_probe_harvest_disables_wayback_and_returns_zero_for_negative(monkeypatch):
    command = _command("recon.http_probe_and_harvest", {"host": "vuln-target"})
    context = Context(command)
    wayback_calls = 0

    async def no_probe(_host):
        return None

    async def wayback(_host):
        nonlocal wayback_calls
        wayback_calls += 1
        return []

    monkeypatch.setattr(httpprobe, "ScopeClient", lambda *a, **k: AllowedScope())
    monkeypatch.setattr(httpprobe, "_probe", no_probe)
    monkeypatch.setattr(httpprobe, "_wayback", wayback)
    monkeypatch.setattr(httpprobe, "RECON_EXTERNAL_SOURCES_ENABLED", False)
    result = asyncio.run(httpprobe.handle_http_probe_and_harvest(context, command))
    assert result.result_count == 0
    assert context.results == []
    assert wayback_calls == 0


def test_http_probe_publishes_endpoint_and_page_results_before_return(monkeypatch):
    command = _command("recon.http_probe_and_harvest", {"host": "vuln-target"})
    context = Context(command)
    monkeypatch.setattr(httpprobe, "ScopeClient", lambda *a, **k: AllowedScope())
    monkeypatch.setattr(httpprobe, "_probe", lambda host: asyncio.sleep(0, result={"host": host, "url": "http://vuln-target/", "status": 200}))
    monkeypatch.setattr(httpprobe, "_crawl_links", lambda url: asyncio.sleep(0, result=["http://vuln-target/page"]))
    monkeypatch.setattr(httpprobe, "RECON_EXTERNAL_SOURCES_ENABLED", False)
    result = asyncio.run(httpprobe.handle_http_probe_and_harvest(context, command))
    assert result.result_count == 2
    assert [topic for topic, *_ in context.results] == ["asset.endpoint.alive", "asset.url.collected"]


def test_port_and_fuzz_handlers_report_zero_and_correlated_results(monkeypatch):
    port_command = _command("recon.port_scan", {"ip": "172.20.0.9"})
    fuzz_command = _command("recon.content_fuzz", {"base_url": "http://vuln-target/"})
    port_context, fuzz_context = Context(port_command), Context(fuzz_command)
    monkeypatch.setattr(portfuzz, "ScopeClient", lambda *a, **k: AllowedScope())
    monkeypatch.setattr(portfuzz, "scan_ports_operation", lambda ip: asyncio.sleep(0, result=[]))
    monkeypatch.setattr(portfuzz, "fuzz_content_operation", lambda url: asyncio.sleep(0, result=[{"url": "http://vuln-target/.env", "path": ".env", "status": 200, "length": 20}]))
    port_result = asyncio.run(portfuzz.handle_port_scan(port_context, port_command))
    fuzz_result = asyncio.run(portfuzz.handle_content_fuzz(fuzz_context, fuzz_command))
    assert port_result.result_count == 0
    assert fuzz_result.result_count == 1
    assert fuzz_context.results[0][1]["result_id"].startswith("sha256:")


class HostsAndIps:
    def __init__(self, allowed):
        self.allowed = set(allowed)

    async def permits(self, target):
        return target in self.allowed


def test_port_scan_refuses_public_ip_unless_that_ip_is_in_scope(monkeypatch):
    scanned = []

    async def operation(ip):
        scanned.append(ip)
        return []

    monkeypatch.setattr(portfuzz, "scan_ports_operation", operation)
    command = _command("recon.port_scan", {"ip": "93.184.216.34", "scope_host": "vuln-target"})

    # hostname is in scope, but the resolved public IP is not: must not be scanned
    monkeypatch.setattr(portfuzz, "ScopeClient", lambda *a, **k: HostsAndIps({"vuln-target"}))
    blocked = asyncio.run(portfuzz.handle_port_scan(Context(command), command))
    assert blocked.result_count == 0
    assert blocked.outcome == {"skipped": "ip_not_in_scope"}
    assert scanned == []

    # once the IP itself is confirmed in scope it may be scanned
    monkeypatch.setattr(portfuzz, "ScopeClient", lambda *a, **k: HostsAndIps({"vuln-target", "93.184.216.34"}))
    allowed = asyncio.run(portfuzz.handle_port_scan(Context(command), command))
    assert allowed.result_count == 0 and allowed.outcome is None
    assert scanned == ["93.184.216.34"]


def test_port_scan_allows_private_and_loopback_ips_of_in_scope_hosts(monkeypatch):
    scanned = []

    async def operation(ip):
        scanned.append(ip)
        return []

    monkeypatch.setattr(portfuzz, "scan_ports_operation", operation)
    monkeypatch.setattr(portfuzz, "ScopeClient", lambda *a, **k: HostsAndIps({"vuln-target"}))
    for ip in ("172.20.0.9", "10.1.2.3", "192.168.1.5", "127.0.0.1"):
        command = _command("recon.port_scan", {"ip": ip, "scope_host": "vuln-target"})
        asyncio.run(portfuzz.handle_port_scan(Context(command), command))
    assert scanned == ["172.20.0.9", "10.1.2.3", "192.168.1.5", "127.0.0.1"]
