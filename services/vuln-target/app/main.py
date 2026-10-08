"""Demo target — a fake eyewear storefront (for end-to-end testing ONLY).

The front-of-house is a presentable optical shop ("Lumière Eyewear") so the
target can be opened in a browser during a demo. Behind it, the same
intentionally-vulnerable endpoints remain so the VTS pipeline keeps finding
real, in-scope, non-destructive issues fully offline:

  * /.env                -> env-file-exposure           (high)
  * /.git/config         -> git-config-exposure          (medium)
  * /phpinfo.php         -> phpinfo-disclosure            (medium)
  * /actuator/health     -> spring-actuator-exposure      (medium, json)
  * /?q=<reflected>      -> reflected XSS (specialized probe)

It is NOT part of the product; keep it out of real deployments.
"""
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse

app = FastAPI(title="Lumière Eyewear (VTS demo target)")

# --------------------------------------------------------------------------
# Catalogue data (static; a real shop would read this from a database).
# --------------------------------------------------------------------------
PRODUCTS = [
    {"id": "aurora", "name": "Aurora", "type": "Gọng kim loại · Tròn",
     "price": 1_290_000, "c1": "#d9a441", "c2": "#8c6b2f", "tag": "Bán chạy"},
    {"id": "milano", "name": "Milano", "type": "Acetate · Vuông",
     "price": 1_690_000, "c1": "#2f6f6b", "c2": "#1d4442", "tag": "Mới"},
    {"id": "dune", "name": "Dune", "type": "Mắt mèo · Nữ",
     "price": 1_450_000, "c1": "#c06a52", "c2": "#7d3d2d", "tag": ""},
    {"id": "atlas", "name": "Atlas", "type": "Phi công · Kính râm",
     "price": 1_890_000, "c1": "#3b5a7a", "c2": "#223850", "tag": "Phân cực"},
    {"id": "iris", "name": "Iris", "type": "Gọng khoan · Tối giản",
     "price": 2_190_000, "c1": "#8a5a9b", "c2": "#523661", "tag": "Cao cấp"},
    {"id": "nova", "name": "Nova", "type": "Thể thao · Chống trượt",
     "price": 1_150_000, "c1": "#444c56", "c2": "#2b3139", "tag": ""},
]


def _vnd(n: int) -> str:
    return f"{n:,}".replace(",", ".") + "₫"


def _glasses_svg(c1: str, c2: str) -> str:
    """A small inline SVG illustration of a pair of glasses (no external assets)."""
    return f"""<svg viewBox="0 0 220 90" width="100%" height="140" role="img" aria-label="glasses">
      <defs><linearGradient id="g{c1[1:]}" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/>
      </linearGradient></defs>
      <g fill="none" stroke="url(#g{c1[1:]})" stroke-width="6" stroke-linecap="round">
        <rect x="14" y="26" rx="20" ry="20" width="78" height="46"/>
        <rect x="128" y="26" rx="20" ry="20" width="78" height="46"/>
        <path d="M92 40 q18 -10 36 0"/>
        <path d="M14 36 l-10 -6"/><path d="M206 36 l10 -6"/>
      </g>
    </svg>"""


def _product_card(p: dict) -> str:
    tag = f'<span class="tag">{p["tag"]}</span>' if p["tag"] else ""
    return f"""<article class="card">
      <div class="thumb" style="--a:{p['c1']};--b:{p['c2']}">{_glasses_svg(p['c1'], p['c2'])}{tag}</div>
      <div class="cardbody">
        <h3>{p['name']}</h3>
        <p class="type">{p['type']}</p>
        <div class="row"><span class="price">{_vnd(p['price'])}</span>
          <button class="buy">Thêm vào giỏ</button></div>
      </div>
    </article>"""


PAGE_CSS = """
:root{--ink:#1c1a17;--muted:#6f675c;--line:#e7e0d4;--bg:#faf6ef;--card:#fffdf9;
      --accent:#b9822f;--accent2:#8c6b2f;--radius:16px}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;color:var(--ink);
     background:var(--bg);line-height:1.55}
a{color:inherit;text-decoration:none}
.wrap{max-width:1120px;margin:0 auto;padding:0 20px}
header.top{position:sticky;top:0;z-index:5;background:rgba(250,246,239,.9);
     backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.nav{display:flex;align-items:center;gap:22px;height:68px}
.brand{font-family:Georgia,'Times New Roman',serif;font-size:1.5rem;font-weight:700;
     letter-spacing:.5px}
.brand span{color:var(--accent)}
.nav .links{display:flex;gap:20px;margin-left:8px}
.nav .links a{color:var(--muted);font-size:.95rem}
.nav .links a:hover{color:var(--ink)}
.nav form{margin-left:auto;display:flex;gap:8px}
.nav input[type=search]{border:1px solid var(--line);background:#fff;border-radius:999px;
     padding:9px 16px;width:220px;font-size:.9rem;outline:none}
.nav input:focus{border-color:var(--accent)}
.nav .cart{border:1px solid var(--line);border-radius:999px;padding:9px 14px;background:#fff;cursor:pointer}
.hero{padding:64px 0 40px;display:grid;grid-template-columns:1.1fr .9fr;gap:30px;align-items:center}
.hero h1{font-family:Georgia,serif;font-size:3rem;line-height:1.1;margin:0 0 14px}
.hero p{color:var(--muted);font-size:1.1rem;max-width:460px}
.hero .cta{margin-top:22px;display:flex;gap:12px}
.btn{border:none;border-radius:999px;padding:13px 26px;font-size:1rem;cursor:pointer;font-weight:600}
.btn.primary{background:var(--accent);color:#fff}
.btn.primary:hover{background:var(--accent2)}
.btn.ghost{background:transparent;border:1px solid var(--ink)}
.heroart{background:linear-gradient(135deg,#f3ead8,#e9dcc2);border-radius:28px;
     padding:40px;display:flex;align-items:center;justify-content:center;min-height:260px}
.heroart svg{filter:drop-shadow(0 10px 20px rgba(0,0,0,.12))}
.strip{display:flex;gap:14px;justify-content:center;flex-wrap:wrap;color:var(--muted);
     font-size:.9rem;padding:8px 0 40px}
.strip span{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 16px}
h2.section{font-family:Georgia,serif;font-size:1.8rem;margin:10px 0 6px}
.sub{color:var(--muted);margin:0 0 22px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
     overflow:hidden;transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-4px);box-shadow:0 14px 30px rgba(0,0,0,.08)}
.thumb{position:relative;background:linear-gradient(135deg,color-mix(in srgb,var(--a) 22%,#fff),
     color-mix(in srgb,var(--b) 18%,#fff));padding:26px 22px}
.tag{position:absolute;top:12px;left:12px;background:var(--accent);color:#fff;
     font-size:.72rem;font-weight:700;padding:4px 10px;border-radius:999px;letter-spacing:.3px}
.cardbody{padding:16px 18px 20px}
.cardbody h3{margin:0;font-size:1.15rem}
.type{color:var(--muted);font-size:.88rem;margin:4px 0 14px}
.row{display:flex;align-items:center;justify-content:space-between}
.price{font-weight:700;font-size:1.05rem}
.buy{border:1px solid var(--accent);color:var(--accent);background:#fff;border-radius:999px;
     padding:8px 14px;font-size:.85rem;cursor:pointer}
.buy:hover{background:var(--accent);color:#fff}
.searchnote{background:#fff;border:1px solid var(--line);border-left:4px solid var(--accent);
     border-radius:10px;padding:14px 18px;margin:0 0 26px}
footer{margin-top:60px;border-top:1px solid var(--line);background:#fff}
.foot{display:grid;grid-template-columns:2fr 1fr 1fr;gap:24px;padding:40px 0}
.foot h4{margin:0 0 10px;font-size:.95rem}
.foot a,.foot p{display:block;color:var(--muted);font-size:.9rem;margin:6px 0}
.copy{border-top:1px solid var(--line);padding:16px 0;color:var(--muted);font-size:.85rem;text-align:center}
@media(max-width:860px){.hero{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}
     .nav .links{display:none}.foot{grid-template-columns:1fr}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.nav input[type=search]{width:140px}}
"""


def _render_home(q: str) -> str:
    # NOTE: `q` is intentionally reflected UNescaped below — this is the demo
    # reflected-XSS sink the specialized scanner looks for. Do not "fix" it; it
    # is the point of this deliberately-vulnerable target.
    search_note = (
        f'<div class="wrap"><div class="searchnote">Kết quả tìm kiếm cho: '
        f'<strong>{q}</strong> — hiện chưa có sản phẩm khớp, xem gợi ý bên dưới.</div></div>'
        if q else ""
    )
    cards = "".join(_product_card(p) for p in PRODUCTS)
    big = _glasses_svg("#b9822f", "#8c6b2f")
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lumière Eyewear — Kính mắt thời trang &amp; cao cấp</title>
<style>{PAGE_CSS}</style></head><body>
<header class="top"><div class="wrap"><nav class="nav">
  <a class="brand" href="/">Lumière<span>.</span></a>
  <div class="links"><a href="/">Trang chủ</a><a href="#bestsellers">Sản phẩm</a>
    <a href="#">Gọng kính</a><a href="#">Kính râm</a><a href="#">Về chúng tôi</a></div>
  <form method="get" action="/">
    <input type="search" name="q" placeholder="Tìm kính, gọng, thương hiệu..." value="{q}">
    <button class="cart" type="submit">Tìm</button>
  </form>
  <button class="cart">🛒 Giỏ (0)</button>
</nav></div></header>

<main>
<section class="wrap hero">
  <div>
    <h1>Nhìn rõ hơn.<br>Phong cách hơn.</h1>
    <p>Bộ sưu tập gọng kính và kính râm thiết kế thủ công, tròng chống ánh sáng xanh,
       bảo hành 24 tháng. Giao hàng toàn quốc, đổi trả trong 7 ngày.</p>
    <div class="cta">
      <button class="btn primary">Mua ngay</button>
      <button class="btn ghost">Đặt lịch đo mắt</button>
    </div>
  </div>
  <div class="heroart">{big}</div>
</section>

<div class="strip wrap">
  <span>🚚 Miễn phí vận chuyển từ 500K</span>
  <span>🔍 Đo mắt miễn phí</span>
  <span>🛡️ Bảo hành 24 tháng</span>
  <span>↩️ Đổi trả 7 ngày</span>
</div>

{search_note}

<section class="wrap" id="bestsellers">
  <h2 class="section">Sản phẩm nổi bật</h2>
  <p class="sub">Những mẫu được khách hàng yêu thích nhất mùa này.</p>
  <div class="grid">{cards}</div>
</section>
</main>

<footer><div class="wrap foot">
  <div><div class="brand" style="font-size:1.3rem">Lumière<span>.</span></div>
    <p>Hệ thống cửa hàng kính mắt cao cấp. Tận tâm cho đôi mắt của bạn.</p>
    <p>123 Đường Láng, Hà Nội · 1900 1234</p></div>
  <div><h4>Cửa hàng</h4><a href="#">Gọng kính</a><a href="#">Kính râm</a>
    <a href="#">Tròng kính</a><a href="#">Phụ kiện</a></div>
  <div><h4>Hỗ trợ</h4><a href="#">Chính sách bảo hành</a><a href="#">Hướng dẫn chọn size</a>
    <a href="/.well-known/security.txt">Bảo mật</a><a href="#">Liên hệ</a></div>
</div><div class="copy">© 2026 Lumière Eyewear — Website demo cho hệ thống VTS (chỉ dùng kiểm thử).</div></footer>
</body></html>"""


# --------------------------------------------------------------------------
# Storefront (browsable)
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    q = request.query_params.get("q", "")
    return _render_home(q)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# Intentionally-vulnerable endpoints (demo only) — DO NOT add to real sites.
# --------------------------------------------------------------------------
@app.get("/.env", response_class=PlainTextResponse)
async def env():
    return "DB_PASSWORD=supersecret123\nSECRET_KEY=demo-leak\nAPI_KEY=abcd1234\n"


@app.get("/.git/config", response_class=PlainTextResponse)
async def git_config():
    return ("[core]\n\trepositoryformatversion = 0\n"
            "[remote \"origin\"]\n\turl = https://example.com/demo.git\n")


@app.get("/phpinfo.php", response_class=HTMLResponse)
async def phpinfo():
    return "<html><body><h1>phpinfo()</h1><p>PHP Version 8.1.2</p></body></html>"


@app.get("/actuator/health")
async def actuator():
    return JSONResponse({"status": "UP", "components": {"db": {"status": "UP"}}})
