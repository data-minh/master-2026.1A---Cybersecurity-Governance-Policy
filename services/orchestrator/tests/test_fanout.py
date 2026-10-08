from datetime import datetime, timezone
from uuid import UUID, uuid4

from services.orchestrator.app.fanout import (
    VTS_UUID_NAMESPACE,
    canonicalize_resource,
    canonicalize_url,
    fan_out,
    make_approval_id,
    make_finding_id,
    make_result_id,
    make_stage_run_id,
    make_work_id,
)
from vts_common.lifecycle import (
    ApprovalSummary,
    LifecycleEnvelopeV1,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
    WorkType,
)

NOW = datetime.now(timezone.utc)


def _snapshot(mode="full"):
    scan_id = str(uuid4())
    stages = {
        name: StageSnapshot(
            stage_run_id=make_stage_run_id(scan_id, name),
            name=name,
            status=StageStatus.RUNNING if name == "recon" else StageStatus.PENDING,
            sealed=False,
        )
        for name in ("recon", "scan", "verification")
    }
    return ScanSnapshot(
        scan_id=scan_id,
        revision=1,
        status=ScanStatus.RUNNING,
        target="vuln-target",
        mode=mode,
        exec_mode="parallel",
        created_at=NOW,
        queued_at=NOW,
        started_at=NOW,
        updated_at=NOW,
        stages=stages,
        approval_summary=ApprovalSummary(),
        result_summary=ResultSummary(),
    )


def _event(snapshot, topic, producer, data):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": topic,
            "scan_id": snapshot.scan_id,
            "stage_run_id": snapshot.stages["recon"].stage_run_id,
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": producer,
            "attempt": 1,
            "occurred_at": NOW.isoformat(),
            "data": data,
        }
    )


def test_canonical_url_and_work_identity_dedupe_logical_resource():
    a = "HTTP://Example.COM:80?a=2&b=1#x"
    b = "http://example.com/?b=1&a=2"
    scan = str(uuid4())

    assert canonicalize_url(a) == "http://example.com/?a=2&b=1"
    assert make_work_id(scan, "scan.template_url", a, "default") == make_work_id(
        scan, "scan.template_url", b, "default"
    )
    assert VTS_UUID_NAMESPACE == UUID("734ed946-af54-58ae-93a9-a429bb322868")


def test_endpoint_fans_out_content_fuzz_and_template_for_full_mode():
    snapshot = _snapshot("full")
    event = _event(
        snapshot,
        "asset.endpoint.alive",
        "recon-httpprobe",
        {"result_id": "sha256:" + "a" * 64, "url": "http://vuln-target/"},
    )
    work = fan_out(event, snapshot)

    assert {item.work_type for item in work} == {
        WorkType.RECON_CONTENT_FUZZ,
        WorkType.SCAN_TEMPLATE_URL,
    }
    assert all(item.parent_work_id == event.work_id for item in work)


def test_subdomain_fanout_respects_active_and_passive_modes():
    active = _snapshot("full")
    passive = _snapshot("recon-passive")
    data = {
        "result_id": "sha256:" + "b" * 64,
        "host": "vuln-target",
        "ip": "172.20.0.9",
    }

    active_types = {
        item.work_type
        for item in fan_out(
            _event(active, "asset.subdomain.discovered", "recon-subdomain", data),
            active,
        )
    }
    passive_types = {
        item.work_type
        for item in fan_out(
            _event(passive, "asset.subdomain.discovered", "recon-subdomain", data),
            passive,
        )
    }
    assert active_types == {
        WorkType.RECON_HTTP_PROBE_AND_HARVEST,
        WorkType.RECON_PORT_SCAN,
    }
    port_work = next(
        item
        for item in fan_out(
            _event(active, "asset.subdomain.discovered", "recon-subdomain", data),
            active,
        )
        if item.work_type is WorkType.RECON_PORT_SCAN
    )
    assert port_work.input["scope_host"] == "vuln-target"
    assert passive_types == {WorkType.RECON_HTTP_PROBE_AND_HARVEST}


def test_page_url_fans_out_both_scanners_but_non_page_does_not():
    snapshot = _snapshot()
    page = _event(
        snapshot,
        "asset.url.collected",
        "recon-httpprobe",
        {
            "result_id": "sha256:" + "c" * 64,
            "url": "http://vuln-target/a",
            "class": "page",
        },
    )
    non_page = page.model_copy(
        update={"data": {**page.data, "class": "script"}}
    )
    assert {item.work_type for item in fan_out(page, snapshot)} == {
        WorkType.SCAN_TEMPLATE_URL,
        WorkType.SCAN_SPECIALIZED_URL,
    }
    assert fan_out(non_page, snapshot) == []


def test_only_high_or_critical_findings_create_safe_verify():
    snapshot = _snapshot()
    high = _event(
        snapshot,
        "vuln.detected",
        "scan-engine",
        {
            "result_id": "sha256:" + "d" * 64,
            "finding_id": "sha256:" + "e" * 64,
            "url": "http://vuln-target/",
            "severity": "high",
        },
    )
    low = high.model_copy(update={"data": {**high.data, "severity": "low"}})
    assert [item.work_type for item in fan_out(high, snapshot)] == [
        WorkType.VERIFICATION_SAFE_VERIFY
    ]
    assert fan_out(low, snapshot) == []


def test_approval_request_creates_blocked_execute_work():
    snapshot = _snapshot()
    approval_id = str(uuid4())
    event = _event(
        snapshot,
        "approval.requested",
        "verification",
        {
            "approval_id": approval_id,
            "finding_id": "sha256:" + "f" * 64,
            "execution_work_id": str(uuid4()),
            "decision_deadline": NOW.isoformat(),
        },
    )
    work = fan_out(event, snapshot)
    assert len(work) == 1
    assert work[0].work_type == WorkType.VERIFICATION_EXECUTE
    assert work[0].dispatch_state == "blocked_approval"
    assert work[0].input == {"approval_id": approval_id, "dry_run": True}


def test_result_finding_and_approval_ids_are_stable():
    scan = str(uuid4())
    assert canonicalize_resource("VULN-TARGET") == "vuln-target"
    assert make_stage_run_id(scan, "scan") == make_stage_run_id(scan, "scan")
    assert make_result_id(scan, "asset.url.collected", "http://VULN-TARGET", "page") == make_result_id(
        scan, "asset.url.collected", "http://vuln-target/", "page"
    )
    finding = make_finding_id(scan, "http://vuln-target/", "template", "default")
    assert finding.startswith("sha256:")
    assert make_approval_id(finding) == make_approval_id(finding)
