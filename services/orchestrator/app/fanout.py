"""Deterministic identities and the fixed VTS streaming DAG."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid5

from vts_common.config import settings
from vts_common.lifecycle import LifecycleEnvelopeV1, ScanSnapshot, WorkType

VTS_UUID_NAMESPACE = UUID("734ed946-af54-58ae-93a9-a429bb322868")

SERVICE_BY_WORK = {
    WorkType.RECON_BOOTSTRAP: "recon-subdomain",
    WorkType.RECON_HTTP_PROBE_AND_HARVEST: "recon-httpprobe",
    WorkType.RECON_PORT_SCAN: "recon-portfuzz",
    WorkType.RECON_CONTENT_FUZZ: "recon-portfuzz",
    WorkType.SCAN_TEMPLATE_URL: "scan-engine",
    WorkType.SCAN_SPECIALIZED_URL: "scan-specialized",
    WorkType.VERIFICATION_SAFE_VERIFY: "verification",
    WorkType.VERIFICATION_EXECUTE: "verification",
}
STAGE_BY_WORK = {
    work_type: work_type.value.split(".", 1)[0]
    if not work_type.value.startswith("verification.")
    else "verification"
    for work_type in WorkType
}
TIMEOUT_BY_WORK = {
    WorkType.RECON_BOOTSTRAP: settings.WORK_BOOTSTRAP_TIMEOUT_SECONDS,
    WorkType.RECON_HTTP_PROBE_AND_HARVEST: settings.WORK_HTTP_PROBE_TIMEOUT_SECONDS,
    WorkType.RECON_PORT_SCAN: settings.WORK_PORT_TIMEOUT_SECONDS,
    WorkType.RECON_CONTENT_FUZZ: settings.WORK_FUZZ_TIMEOUT_SECONDS,
    WorkType.SCAN_TEMPLATE_URL: settings.WORK_TEMPLATE_TIMEOUT_SECONDS,
    WorkType.SCAN_SPECIALIZED_URL: settings.WORK_SPECIALIZED_TIMEOUT_SECONDS,
    WorkType.VERIFICATION_SAFE_VERIFY: settings.WORK_SAFE_VERIFY_TIMEOUT_SECONDS,
    WorkType.VERIFICATION_EXECUTE: settings.WORK_EXECUTE_TIMEOUT_SECONDS,
}


@dataclass(frozen=True, slots=True)
class WorkSpec:
    work_type: WorkType
    service: str
    stage: str
    scan_id: str
    stage_run_id: str
    work_id: str
    parent_work_id: str | None
    input: dict
    variant: str
    timeout_seconds: int
    max_attempts: int = 3
    dispatch_state: str = "ready"


def canonicalize_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("resource is not an HTTP URL")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        pass
    port = parsed.port
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, host, path, query, ""))


def canonicalize_resource(value: str) -> str:
    if "://" in value:
        return canonicalize_url(value)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower().rstrip(".")


def make_stage_run_id(scan_id: str, stage: str) -> str:
    return str(uuid5(VTS_UUID_NAMESPACE, f"stage|{scan_id}|{stage}"))


def make_work_id(
    scan_id: str,
    work_type: WorkType | str,
    resource: str,
    variant: str,
) -> str:
    typed = WorkType(work_type)
    canonical = canonicalize_resource(resource)
    return str(
        uuid5(
            VTS_UUID_NAMESPACE,
            f"work|{scan_id}|{typed.value}|{canonical}|{variant}",
        )
    )


def _sha256_identity(*parts: str) -> str:
    value = "|".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def make_result_id(
    scan_id: str, topic: str, resource: str, variant: str = "default"
) -> str:
    return _sha256_identity(
        "result", scan_id, topic, canonicalize_resource(resource), variant
    )


def make_finding_id(
    scan_id: str,
    url: str,
    template_id: str,
    probe_variant: str = "default",
) -> str:
    return _sha256_identity(
        "finding",
        scan_id,
        canonicalize_url(url),
        template_id,
        probe_variant,
    )


def make_approval_id(finding_id: str) -> str:
    return str(uuid5(VTS_UUID_NAMESPACE, f"approval|{finding_id}"))


def fan_out(
    event: LifecycleEnvelopeV1, snapshot: ScanSnapshot
) -> list[WorkSpec]:
    data = event.data
    specs: list[WorkSpec] = []

    if event.event == "asset.subdomain.discovered":
        host = data.get("host") or data.get("subdomain")
        if not host:
            return []
        specs.append(
            _spec(
                snapshot,
                event,
                WorkType.RECON_HTTP_PROBE_AND_HARVEST,
                host,
                {"host": canonicalize_resource(host)},
            )
        )
        if snapshot.mode != "recon-passive" and data.get("ip"):
            specs.append(
                _spec(
                    snapshot,
                    event,
                    WorkType.RECON_PORT_SCAN,
                    data["ip"],
                    {
                        "ip": canonicalize_resource(data["ip"]),
                        "scope_host": canonicalize_resource(host),
                    },
                )
            )
    elif event.event == "asset.endpoint.alive":
        url = data.get("url") or data.get("endpoint")
        if not url:
            return []
        if snapshot.mode != "recon-passive":
            specs.append(
                _spec(
                    snapshot,
                    event,
                    WorkType.RECON_CONTENT_FUZZ,
                    url,
                    {"base_url": canonicalize_url(url)},
                )
            )
        if snapshot.mode == "full":
            specs.append(
                _spec(
                    snapshot,
                    event,
                    WorkType.SCAN_TEMPLATE_URL,
                    url,
                    {"url": canonicalize_url(url), "class": "page"},
                )
            )
    elif event.event == "asset.url.collected":
        if data.get("class") != "page" or snapshot.mode != "full":
            return []
        url = data.get("url")
        if not url:
            return []
        for work_type in (
            WorkType.SCAN_TEMPLATE_URL,
            WorkType.SCAN_SPECIALIZED_URL,
        ):
            specs.append(
                _spec(
                    snapshot,
                    event,
                    work_type,
                    url,
                    {"url": canonicalize_url(url), "class": "page"},
                )
            )
    elif event.event == "vuln.detected":
        if snapshot.mode != "full" or data.get("severity") not in {
            "high",
            "critical",
        }:
            return []
        url = data.get("url")
        finding_id = data.get("finding_id")
        if not url or not finding_id:
            return []
        specs.append(
            _spec(
                snapshot,
                event,
                WorkType.VERIFICATION_SAFE_VERIFY,
                finding_id,
                {
                    "finding_id": finding_id,
                    "url": canonicalize_url(url),
                    "severity": data["severity"],
                },
            )
        )
    elif event.event == "approval.requested":
        approval_id = data.get("approval_id")
        if not approval_id:
            return []
        specs.append(
            _spec(
                snapshot,
                event,
                WorkType.VERIFICATION_EXECUTE,
                approval_id,
                {"approval_id": approval_id, "dry_run": True},
                work_id=data.get("execution_work_id"),
                dispatch_state="blocked_approval",
            )
        )
    return specs


def _spec(
    snapshot: ScanSnapshot,
    event: LifecycleEnvelopeV1,
    work_type: WorkType,
    resource: str,
    input_data: dict,
    *,
    variant: str = "default",
    work_id: str | None = None,
    dispatch_state: str = "ready",
) -> WorkSpec:
    stage = STAGE_BY_WORK[work_type]
    return WorkSpec(
        work_type=work_type,
        service=SERVICE_BY_WORK[work_type],
        stage=stage,
        scan_id=snapshot.scan_id,
        stage_run_id=snapshot.stages[stage].stage_run_id,
        work_id=work_id
        or make_work_id(snapshot.scan_id, work_type, resource, variant),
        parent_work_id=event.work_id,
        input=input_data,
        variant=variant,
        timeout_seconds=TIMEOUT_BY_WORK[work_type],
        max_attempts=settings.WORK_MAX_ATTEMPTS,
        dispatch_state=dispatch_state,
    )
