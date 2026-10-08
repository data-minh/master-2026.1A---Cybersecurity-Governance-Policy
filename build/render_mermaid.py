"""Render build/diagrams/*.mmd to PNG with Playwright Chromium + mermaid.js (CDN)."""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

d = Path(__file__).parent / "diagrams"
html = """<!doctype html><html><body style="margin:0;background:#fff">
<div id="out"></div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
</body></html>"""
ok = True
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(device_scale_factor=2, viewport={"width": 1600, "height": 1000})
    page.set_content(html, wait_until="networkidle")
    page.evaluate("mermaid.initialize({startOnLoad:false, theme:'default', securityLevel:'loose', sequence:{useMaxWidth:false}, flowchart:{useMaxWidth:false}, er:{useMaxWidth:false}})")
    for f in sorted(d.glob("*.mmd")):
        code = f.read_text(encoding="utf-8")
        try:
            page.evaluate("""async ([id, code]) => {
                const {svg} = await mermaid.render(id, code);
                document.getElementById('out').innerHTML = svg;
            }""", ["g_" + f.stem, code])
        except Exception as e:
            print("FAIL", f.name, str(e)[:300]); ok = False; continue
        el = page.locator("#out svg")
        el.screenshot(path=str(d / (f.stem + ".png")))
        print("ok", f.name)
    b.close()
sys.exit(0 if ok else 1)
