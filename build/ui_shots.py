"""Capture dashboard screenshots (light/dark, desktop/mobile) from a running stack."""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080"
OUT = Path(__file__).parent / "shots"
OUT.mkdir(exist_ok=True)


def login(page, user):
    page.goto(BASE)
    page.fill("#username", user)
    page.fill("#password", user + "123")
    page.click("#loginForm button[type=submit]")
    page.wait_for_selector("#nav:not([hidden])", timeout=15000)


def shot(page, name):
    page.wait_for_timeout(900)
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    print("saved", name)


with sync_playwright() as p:
    browser = p.chromium.launch()
    for theme in ("light", "dark"):
        ctx = browser.new_context(viewport={"width": 1366, "height": 900}, color_scheme=theme)
        page = ctx.new_page()
        login(page, "admin")
        page.evaluate(f"setTheme('{theme}', false)")
        shot(page, f"{theme}-1-scan")
        page.click('#nav button[data-view="history"]')
        page.wait_for_selector("#historyRows tr[data-id]", timeout=10000)
        shot(page, f"{theme}-2-history")
        page.click("#historyRows tr[data-id]")
        page.wait_for_selector("#hdBody table", timeout=10000)
        page.wait_for_timeout(400)
        page.screenshot(path=str(OUT / f"{theme}-3-history-detail.png"))
        print("saved", f"{theme}-3-history-detail")
        page.click("#hdClose")
        page.click('#nav button[data-view="scope"]')
        page.wait_for_selector("#scopeRows tr")
        shot(page, f"{theme}-4-scope-admin")
        page.click('#nav button[data-view="templates"]')
        page.click("#tplSample")
        page.click("#tplValidate")
        page.wait_for_selector("#tplResult:not([hidden])")
        shot(page, f"{theme}-5-templates")
        ctx.close()

    ctx = browser.new_context(viewport={"width": 1366, "height": 900}, color_scheme="light")
    page = ctx.new_page()
    login(page, "operator")
    nav = page.evaluate("Array.from(document.querySelectorAll('#nav button')).filter(b=>!b.hidden).map(b=>b.textContent.trim())")
    print("operator nav:", nav)
    shot(page, "light-6-operator")
    ctx.close()

    ctx = browser.new_context(viewport={"width": 1366, "height": 900}, color_scheme="light")
    page = ctx.new_page()
    login(page, "approver")
    page.click('#nav button[data-view="scope"]')
    page.wait_for_selector("#scopeRows tr")
    shot(page, "light-7-scope-approver")
    ctx.close()

    ctx = browser.new_context(viewport={"width": 390, "height": 844}, color_scheme="dark", device_scale_factor=2)
    page = ctx.new_page()
    login(page, "admin")
    shot(page, "dark-8-mobile-scan")
    page.click('#nav button[data-view="history"]')
    page.wait_for_selector("#historyRows tr[data-id]")
    shot(page, "dark-9-mobile-history")
    ctx.close()
    browser.close()
