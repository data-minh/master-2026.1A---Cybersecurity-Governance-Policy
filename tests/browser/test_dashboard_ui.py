import pytest
from playwright.sync_api import sync_playwright

from services.dashboard.app.main import INDEX_HTML

XSS = '<img src=x onerror="window.__pwned=1">'


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _page(browser, **kwargs):
    page = browser.new_page(**kwargs)
    # Serve from an http origin so localStorage behaves as it does for real users.
    page.route("http://vts.test/**", lambda route: route.fulfill(
        body=INDEX_HTML, content_type="text/html; charset=utf-8"))
    page.goto("http://vts.test/")
    return page


def _signed_in(page, role):
    page.evaluate(
        "r => { applyRole(r); document.getElementById('loginPanel').hidden = true;"
        " document.getElementById('app').hidden = false; }", role)


def _visible_nav(page):
    return page.evaluate(
        "Array.from(document.querySelectorAll('#nav button[data-view]')).filter(b=>!b.hidden).map(b=>b.dataset.view)"
    )


def test_theme_follows_system_then_toggle_persists_and_updates_label(browser):
    dark = _page(browser, color_scheme="dark")
    assert dark.evaluate("document.documentElement.dataset.theme") == "dark"
    assert "sáng" in dark.locator("#themeToggle").get_attribute("aria-label")
    dark.locator("#themeToggle").click()
    assert dark.evaluate("document.documentElement.dataset.theme") == "light"
    assert dark.evaluate("localStorage.getItem('vts-theme')") == "light"
    assert "tối" in dark.locator("#themeToggle").get_attribute("aria-label")
    assert dark.evaluate("document.getElementById('iconMoon').hasAttribute('hidden')") is False
    assert dark.evaluate("document.getElementById('iconSun').hasAttribute('hidden')") is True

    light = _page(browser, color_scheme="light")
    assert light.evaluate("document.documentElement.dataset.theme") == "light"
    light.evaluate("setTheme('dark', true)")
    assert light.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(12, 18, 23)"
    light.evaluate("setTheme('light', true)")
    assert light.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(241, 243, 246)"


def test_navigation_and_scope_controls_follow_the_signed_in_role(browser):
    page = _page(browser)
    _signed_in(page, "operator")
    assert _visible_nav(page) == ["scan", "history"]  # operator never sees the scope list

    _signed_in(page, "approver")
    assert _visible_nav(page) == ["scan", "history", "scope"]
    page.evaluate("showView('scope')")
    assert page.locator("#scopeReadonly").is_visible()
    assert page.locator("#scopeAdmin").is_hidden()  # read-only for approver
    assert page.locator("#scopeTag").inner_text() == "chỉ xem"

    _signed_in(page, "admin")
    assert _visible_nav(page) == ["scan", "history", "scope", "templates"]
    assert page.locator("#scopeAdmin").is_visible()
    assert page.locator("#scopeReadonly").is_hidden()


def test_views_the_role_cannot_use_fall_back_to_the_scan_view(browser):
    page = _page(browser)
    _signed_in(page, "operator")
    for blocked in ("scope", "templates"):
        page.evaluate(f"showView('{blocked}')")
        assert page.evaluate("activeView") == "scan"
        assert page.locator(f"#view-{blocked}").is_hidden() is True
    _signed_in(page, "admin")
    page.evaluate("showView('templates')")
    assert page.evaluate("activeView") == "templates" and page.locator("#view-templates").is_visible()
    page.evaluate("applyRole('approver')")  # demotion while on a restricted view
    assert page.evaluate("activeView") == "scan"


def test_history_table_shows_results_pages_and_escapes_untrusted_text(browser):
    page = _page(browser)
    _signed_in(page, "admin")
    payload = {
        "total": 2, "limit": 15, "offset": 0,
        "items": [
            {"scan_id": "11111111-1111-4111-8111-111111111111", "target": XSS, "mode": "full",
             "status": "succeeded", "actor": "operator", "created_at": "2026-10-08T10:00:00Z",
             "completed_at": "2026-10-08T10:00:20Z", "duration_seconds": 20,
             "summary": {"assets": 10, "findings": 5, "verified": 2, "execution": 0},
             "findings_by_severity": {"critical": 0, "high": 2, "medium": 3, "low": 0, "info": 0}},
            {"scan_id": "22222222-2222-4222-8222-222222222222", "target": "scanme.nmap.org", "mode": "recon",
             "status": "canceled", "actor": None, "created_at": "2026-10-08T09:00:00Z",
             "completed_at": "2026-10-08T09:01:05Z", "duration_seconds": 65,
             "summary": {"assets": 3, "findings": 0, "verified": 0, "execution": 0},
             "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
        ],
    }
    page.evaluate("p => renderHistoryRows(p)", payload)
    rows = page.locator("#historyRows tr[data-id]")
    assert rows.count() == 2
    assert page.locator("#historyRows img").count() == 0
    assert page.evaluate("window.__pwned || 0") == 0
    assert XSS in rows.nth(0).inner_text()  # shown as text, not executed
    first = rows.nth(0).inner_text()
    assert "Thành công" in first and "Cao 2" in first and "Trung bình 3" in first and "20 giây" in first
    second = rows.nth(1).inner_text()
    assert "Đã hủy" in second and "Không có" in second and "1 phút 5 giây" in second
    assert page.locator("#historyCount").inner_text() == "Hiển thị 1 đến 2 trên 2 lần kiểm tra"
    assert page.locator("#hPrev").is_disabled() and page.locator("#hNext").is_disabled()

    page.evaluate("renderHistoryRows({items: [], total: 0, offset: 0, limit: 15})")
    assert "Chưa có lần kiểm tra nào" in page.locator("#historyRows").inner_text()
    page.evaluate("historyState.status='failed'; renderHistoryRows({items: [], total: 0, offset: 0, limit: 15})")
    assert "khớp bộ lọc" in page.locator("#historyRows").inner_text()


def test_history_detail_lists_findings_and_csv_neutralises_formulas(browser):
    page = _page(browser)
    detail = {
        "scan_id": "11111111-1111-4111-8111-111111111111", "target": "vuln-target", "mode": "full",
        "exec_mode": "parallel", "status": "succeeded", "actor": "approver", "outcome_code": "SCAN_SUCCEEDED",
        "created_at": "2026-10-08T10:00:00Z", "completed_at": "2026-10-08T10:00:20Z", "duration_seconds": 20,
        "summary": {"assets": 10, "findings": 2, "verified": 1, "execution": 0},
        "approvals": {"total": 1, "executed": 1, "rejected": 0, "failed": 0},
        "stages": {"recon": {"status": "succeeded", "total_work": 4, "failed_work": 0, "result_count": 10}},
        "findings": [
            {"severity": "high", "template_id": "env-file-exposure", "name": "Exposed .env", "url": "http://vuln-target/.env"},
            {"severity": "medium", "template_id": "=HYPERLINK(\"http://evil\")", "name": "x,y", "url": XSS},
        ],
    }
    page.evaluate("d => renderHistoryDetail(d)", detail)
    body = page.locator("#hdBody").inner_text()
    assert "env-file-exposure" in body and "Phát hiện (2)" in body and "approver" in body
    assert page.locator("#hdBody img").count() == 0
    csv = page.evaluate("historyCsv(historyDetail)")
    assert "'=HYPERLINK" in csv and '"x,y"' in csv
    assert csv.splitlines()[0] == '"Mức độ","Template","Tên","URL"'


def test_template_list_escapes_ids_and_labels_delete_buttons(browser):
    page = _page(browser)
    _signed_in(page, "admin")
    page.evaluate(
        "items => renderTemplates(items)",
        [{"id": XSS, "parsed": {"info": {"name": "Demo", "severity": "low"}}}],
    )
    assert page.locator("#templateRows img").count() == 0
    assert page.evaluate("window.__pwned || 0") == 0
    assert page.locator("#templateRows .sev.low").count() == 1
    assert "Xóa template" in page.locator("#templateRows button").get_attribute("aria-label")
    page.evaluate("renderTemplates([])")
    assert "Chưa có template nào" in page.locator("#templateRows").inner_text()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_no_horizontal_overflow_on_a_phone_in_both_themes(browser, theme):
    page = _page(browser, viewport={"width": 375, "height": 800})
    page.evaluate(f"setTheme('{theme}', false)")
    _signed_in(page, "admin")
    for view in ("scan", "history", "scope", "templates"):
        page.evaluate(f"showView('{view}')")
        width = page.evaluate("document.documentElement.scrollWidth")
        assert width <= 376, f"{view} overflows at 375px in {theme}: {width}"


def test_skip_link_theme_color_and_progress_bar_follow_the_guidelines(browser):
    page = _page(browser)
    assert page.locator("a.skip").get_attribute("href") == "#main"
    page.evaluate("setTheme('dark', false)")
    assert page.locator("#themeColor").get_attribute("content") == "#0c1217"
    page.evaluate("setTheme('light', false)")
    assert page.locator("#themeColor").get_attribute("content") == "#f1f3f6"

    # a finished stage always shows a full bar even when a work item was canceled
    stage = {"stage_run_id": "s", "name": "x", "status": "succeeded", "sealed": True,
             "total_work": 4, "open_work": 0, "completed_work": 3, "failed_work": 0,
             "timed_out_work": 0, "result_count": 2}
    snapshot = {"scan_id": "11111111-1111-4111-8111-111111111111", "revision": 5, "status": "succeeded",
                "target": "vuln-target", "updated_at": "2026-10-08T10:00:00Z",
                "stages": {n: {**stage, "name": n} for n in ("recon", "scan", "verification")},
                "result_summary": {}, "approval_summary": {}}
    page.evaluate("s => applySnapshot(s)", snapshot)
    assert page.evaluate("document.querySelector('[data-stage=verification] .bar i').style.transform") == "scaleX(1)"
    assert page.locator("#reportLink").get_attribute("download").startswith("bao-cao-")
