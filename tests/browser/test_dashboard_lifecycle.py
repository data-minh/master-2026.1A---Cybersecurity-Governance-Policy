from datetime import datetime, timezone
from uuid import uuid4

from playwright.sync_api import sync_playwright

from services.dashboard.app.main import INDEX_HTML


def _snapshot(revision=1, status="running", stage_status="running", result_count=0):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "lifecycle_version": 1,
        "scan_id": str(uuid4()),
        "revision": revision,
        "status": status,
        "target": "vuln-target",
        "mode": "full",
        "exec_mode": "parallel",
        "created_at": now,
        "updated_at": now,
        "last_progress_at": now,
        "stages": {
            name: {
                "stage_run_id": str(uuid4()),
                "name": name,
                "status": stage_status,
                "sealed": stage_status in {"succeeded", "skipped"},
                "total_work": 1,
                "open_work": 1 if stage_status == "running" else 0,
                "completed_work": 0,
                "failed_work": 0,
                "timed_out_work": 0,
                "result_count": result_count,
            }
            for name in ("recon", "scan", "verification")
        },
        "approval_summary": {"total": 1 if status == "awaiting_approval" else 0, "pending": 1 if status == "awaiting_approval" else 0, "approved_awaiting_execution": 0, "executing": 0, "rejected": 0, "executed": 0, "failed": 0},
        "result_summary": {"assets": 0, "findings": 0, "verified": 0, "execution": 0},
    }


def _page():
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.set_content(INDEX_HTML)
    return playwright, browser, page


def test_three_stages_can_all_render_running_without_closing_recon():
    playwright, browser, page = _page()
    try:
        page.evaluate("snapshot => applySnapshot(snapshot)", _snapshot(2))
        for stage in ("recon", "scan", "verification"):
            assert "running" in page.locator(f'[data-stage="{stage}"]').get_attribute("class")
        assert page.locator("#pipeState").inner_text() == "Đang xử lý"
    finally:
        browser.close()
        playwright.stop()


def test_authoritative_status_labels_include_zero_result_and_approval():
    playwright, browser, page = _page()
    try:
        succeeded = _snapshot(3, "succeeded", "succeeded", 0)
        page.evaluate("snapshot => applySnapshot(snapshot)", succeeded)
        assert "Hoàn tất · 0 kết quả" in page.locator('[data-stage="scan"] .stage-detail').inner_text()
        awaiting = _snapshot(4, "awaiting_approval", "running")
        awaiting["scan_id"] = succeeded["scan_id"]
        page.evaluate("snapshot => applySnapshot(snapshot)", awaiting)
        assert page.locator("#pipeState").inner_text() == "Chờ phê duyệt/thao tác"
    finally:
        browser.close()
        playwright.stop()


def test_delayed_old_revision_cannot_repaint_newer_snapshot():
    playwright, browser, page = _page()
    try:
        newest = _snapshot(8, "failed", "failed")
        older = _snapshot(7, "running", "running")
        older["scan_id"] = newest["scan_id"]
        assert page.evaluate("snapshot => applySnapshot(snapshot)", newest) is True
        assert page.evaluate("snapshot => applySnapshot(snapshot)", older) is False
        assert page.evaluate("lastRevision") == 8
        assert page.locator("#pipeState").inner_text() == "Thất bại"
    finally:
        browser.close()
        playwright.stop()


def test_polling_is_chained_and_connection_state_is_visible():
    playwright, browser, page = _page()
    try:
        assert page.evaluate("typeof openScanStream") == "function"
        assert page.evaluate("typeof startFallbackPolling") == "function"
        assert page.evaluate("typeof stopFallbackPollingAfterStableSse") == "function"
        page.evaluate("setConnectionState('polling')")
        assert page.locator("#connectionState").inner_text() == "Cập nhật dự phòng"
        page.evaluate("setConnectionState('offline')")
        assert "Mất kết nối" in page.locator("#connectionState").inner_text()
        assert page.evaluate("window.__usesSetInterval || false") is False
    finally:
        browser.close()
        playwright.stop()
