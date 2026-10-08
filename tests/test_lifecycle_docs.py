from pathlib import Path

from vts_common.lifecycle import ScanStatus, StageStatus, WorkStatus

ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs" / "BaoCao.md"


def _text():
    return DOC.read_text(encoding="utf-8")


def test_documented_statuses_match_lifecycle_enums():
    text = _text()
    for status in (*ScanStatus, *StageStatus, *WorkStatus):
        assert f"`{status.value}`" in text


def test_documented_runtime_commands_reference_existing_files():
    text = _text()
    for relative in (
        "docker-compose.yml",
        "docker-compose.test.yml",
        "scripts/e2e_test.py",
        "scripts/measure.py",
        "scripts/migrate_legacy_events.py",
        "requirements-dev.txt",
    ):
        assert f"`{relative}`" in text
        assert (ROOT / relative).exists()
    assert "docker compose -p vts-lifecycle-test" in text


def test_docs_describe_aof_rpo_policy_a_and_internal_only_overlay():
    text = _text().lower()
    for phrase in (
        "appendonly yes",
        "appendfsync everysec",
        "rpo",
        "policy a",
        "recon_external_sources_enabled=false",
        "vuln-target",
        "sse",
        "revision",
    ):
        assert phrase in text


def test_docs_do_not_claim_idle_or_finished_as_success():
    text = _text().lower()
    assert "idle-reaper 20s" not in text
    assert "state in-memory" not in text
    assert "running|finished" not in text
    assert "pipeline_total_s=~25-40" not in text
