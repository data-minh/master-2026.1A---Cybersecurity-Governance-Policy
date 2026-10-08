"""Import retained v0 bus history without inferring v1 lifecycle success."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

import redis.asyncio as redis_async

from vts_common.lifecycle import EventValidationError, LegacyEventV0, parse_event


@dataclass(slots=True)
class MigrationReport:
    scanned: int = 0
    v1_ignored: int = 0
    malformed: int = 0
    expired: int = 0
    would_import: int = 0
    imported: int = 0
    already_migrated: int = 0
    v1_conflicts: int = 0
    open_approvals: int = 0


class LegacyMigration:
    def __init__(self, redis, namespace: str = "vts", stream: str = "vts.bus"):
        self.redis = redis
        self.namespace = namespace.rstrip(":")
        self.stream = stream

    def key(self, suffix):
        return f"{self.namespace}:{suffix}"

    async def scan(self, from_id: str, to_id: str, dry_run: bool) -> MigrationReport:
        report = MigrationReport()
        grouped: dict[str, list[LegacyEventV0]] = {}
        entries = await self.redis.xrange(self.stream, min=from_id, max=to_id)
        now = datetime.now(timezone.utc)
        for _message_id, fields in entries:
            report.scanned += 1
            try:
                event = parse_event(fields.get("payload", ""))
            except EventValidationError:
                report.malformed += 1
                continue
            if not isinstance(event, LegacyEventV0):
                report.v1_ignored += 1
                continue
            try:
                occurred = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                occurred = now
            if now - occurred > timedelta(days=7):
                report.expired += 1
                continue
            if event.scan_id:
                grouped.setdefault(event.scan_id, []).append(event)

        for scan_id, events in grouped.items():
            marker = self.key(f"migration:v0:{scan_id}")
            if await self.redis.exists(marker):
                report.already_migrated += 1
                continue
            snapshot_key = self.key(f"scan:{scan_id}:snapshot")
            existing = await self.redis.get(snapshot_key)
            if existing:
                try:
                    if json.loads(existing).get("lifecycle_version") == 1:
                        report.v1_conflicts += 1
                        continue
                except (ValueError, AttributeError):
                    report.v1_conflicts += 1
                    continue

            terminal = any(event.event == "scan.finished" for event in events)
            started = next((event for event in events if event.event == "scan.started"), events[0])
            target = started.data.get("target")
            updated_at = events[-1].timestamp or now.isoformat()
            snapshot = {
                "lifecycle_version": 0,
                "authoritative": False,
                "scan_id": scan_id,
                "target": target,
                "legacy_status": "finished" if terminal else "in_flight",
                "status": "finished" if terminal else "canceled",
                "outcome": None
                if terminal
                else {"type": "canceled", "code": "migration_cutover"},
                "created_at": started.timestamp or updated_at,
                "updated_at": updated_at,
            }
            requested = sum(event.event == "vuln.verified" for event in events)
            resolved = sum(event.event == "exploit.executed" for event in events)
            if requested > resolved:
                report.open_approvals += requested - resolved
            report.would_import += 1
            if dry_run:
                continue
            # Legacy records live in their own keyspace: the v1 scan index and
            # snapshot keys must only ever hold v1 ScanSnapshot documents.
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.set(
                    self.key(f"legacy:scan:{scan_id}:snapshot"),
                    json.dumps(snapshot, ensure_ascii=False),
                )
                pipe.zadd(
                    self.key("legacy:scan:index"),
                    {scan_id: _score(started.timestamp)},
                )
                pipe.set(marker, "1", ex=691_200)
                await pipe.execute()
            report.imported += 1
        return report


def _score(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc).timestamp()


async def _run(args) -> int:
    redis = redis_async.from_url(args.redis_url, decode_responses=True)
    try:
        migration = LegacyMigration(redis)
        report = await migration.scan(args.from_id, args.to_id, args.dry_run)
        print(json.dumps(asdict(report), ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        await redis.aclose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--from-id", default="0-0")
    parser.add_argument("--to-id", default="+")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", dest="dry_run", action="store_false")
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
