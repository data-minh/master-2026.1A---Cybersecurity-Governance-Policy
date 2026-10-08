"""Build BaoCao_VTS.docx from docs/BaoCao_NopBai.md (python-docx).

Mermaid blocks are replaced by pre-rendered PNGs (build/render_mermaid.py),
in document order: architecture, sequence, ER. Image links are embedded as-is.
"""
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
MD = ROOT / "docs" / "BaoCao_NopBai.md"
DIA = ROOT / "build" / "diagrams"
OUT = ROOT / "BaoCao_VTS.docx"
MERMAID_IMAGES = ["kien_truc.png", "tuan_tu.png", "er_redis.png", "er_history.png"]
SHOTS = ROOT / "build" / "shots"
CAPTIONS = {
    "kien_truc.png": "Hình 1. Kiến trúc hệ thống",
    "usecase_tong_quan.png": "Hình 2. Use case tổng quan (phân quyền theo vai trò)",
    "usecase_uc2.png": "Hình 3. Phân rã UC2 — Phạm vi được phép",
    "usecase_uc3.png": "Hình 4. Phân rã UC3 — Khởi chạy phiên quét",
    "usecase_uc6.png": "Hình 5. Phân rã UC6 — Phê duyệt và thực thi",
    "usecase_uc7.png": "Hình 6. Phân rã UC7 — Quản lý template (admin)",
    "usecase_uc12.png": "Hình 7. Phân rã UC12 — Lịch sử kiểm tra",
    "tuan_tu.png": "Hình 8. Sơ đồ tuần tự — luồng chính",
    "hoat_dong.png": "Hình 9. Sơ đồ hoạt động — luồng chính",
    "er_redis.png": "Hình 10. Mô hình dữ liệu logic (Redis)",
    "er_history.png": "Hình 11. Lược đồ SQLite — lịch sử kiểm tra",
    "light-1-scan.png": "Hình 12. Phiên quét (chế độ sáng)",
    "dark-1-scan.png": "Hình 13. Phiên quét (chế độ tối)",
    "light-2-history.png": "Hình 14. Lịch sử kiểm tra (sáng)",
    "light-3-history-detail.png": "Hình 15. Chi tiết một lần kiểm tra (sáng)",
    "light-4-scope-admin.png": "Hình 16. Phạm vi — admin (sáng)",
    "light-7-scope-approver.png": "Hình 17. Phạm vi — approver chỉ xem (sáng)",
    "dark-5-templates.png": "Hình 18. Quản lý template — admin (tối)",
    "light-6-operator.png": "Hình 19. Operator chỉ thấy hai mục (sáng)",
    "dark-9-mobile-history.png": "Hình 20. Điện thoại — lịch sử (tối)",
}
EXTRA_AFTER_42 = ["usecase_uc2.png", "usecase_uc3.png", "usecase_uc6.png", "usecase_uc7.png", "usecase_uc12.png"]
FONT = "Calibri"

doc = Document()
sec = doc.sections[0]
sec.page_width, sec.page_height = Cm(21), Cm(29.7)
sec.left_margin = sec.right_margin = Cm(2.0)
sec.top_margin = sec.bottom_margin = Cm(2.0)
CONTENT_W = 17.0


def set_font(style, size, bold=None, color=None):
    style.font.name = FONT
    style.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    style.font.size = Pt(size)
    if bold is not None:
        style.font.bold = bold
    if color:
        style.font.color.rgb = RGBColor(*color)


set_font(doc.styles["Normal"], 11)
doc.styles["Normal"].paragraph_format.space_after = Pt(5)
set_font(doc.styles["Heading 1"], 17, True, (0x1F, 0x2F, 0x5F))
set_font(doc.styles["Heading 2"], 13.5, True, (0x1F, 0x2F, 0x5F))
set_font(doc.styles["Heading 3"], 11.5, True, (0x2F, 0x40, 0x7A))
for name in ("Heading 1", "Heading 2", "Heading 3"):
    doc.styles[name].paragraph_format.space_before = Pt(12)
    doc.styles[name].paragraph_format.space_after = Pt(5)
    doc.styles[name].paragraph_format.keep_with_next = True


def shade(cell_or_par, fill, par=False):
    pr = cell_or_par._p.get_or_add_pPr() if par else cell_or_par._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")


def add_inline(par, text, size=None, bold=False):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            run = par.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = par.add_run(part[1:-1])
            run.font.name = "Consolas"
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
            run.font.size = Pt((size or 11) - 1.5)
            run.font.color.rgb = RGBColor(0x8A, 0x1F, 0x4F)
        elif part.startswith("["):
            m = re.match(r"\[([^\]]+)\]\(([^)]+)\)", part)
            run = par.add_run(m.group(1))
            run.font.color.rgb = RGBColor(0x1F, 0x4F, 0xA0)
        else:
            run = par.add_run(part)
        if bold:
            run.bold = True
        if size and not (part.startswith("`")):
            run.font.size = Pt(size)


def add_image(name, alt=""):
    path = DIA / name
    if not path.exists():
        path = SHOTS / name
    if not path.exists():
        raise SystemExit(f"missing image {path}")
    from PIL import Image

    w, h = Image.open(path).size
    width_cm = CONTENT_W
    height_cm = width_cm * h / w
    if height_cm > 21:
        width_cm = width_cm * 21 / height_cm
    if w < 900 and width_cm > 9:
        width_cm = 9
    par = doc.add_paragraph()
    par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    par.paragraph_format.keep_with_next = True
    par.add_run().add_picture(str(path), width=Cm(width_cm))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run(CAPTIONS.get(name, alt))
    r.italic = True
    r.font.size = Pt(9.5)


def add_table(rows):
    header, body = rows[0], rows[2:]
    ncol = len(header)
    table = doc.add_table(rows=1, cols=ncol)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, cell_text in enumerate(header):
        cell = table.rows[0].cells[i]
        cell.text = ""
        add_inline(cell.paragraphs[0], cell_text.strip(), size=9.5, bold=True)
        shade(cell, "DFE8FF")
    for row in body:
        cells = table.add_row().cells
        for i in range(ncol):
            txt = row[i].strip() if i < len(row) else ""
            cells[i].text = ""
            add_inline(cells[i].paragraphs[0], txt, size=9.5)
    for row in table.rows:
        for cell in row.cells:
            for par in cell.paragraphs:
                par.paragraph_format.space_after = Pt(1)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def add_code(lines):
    for line in lines:
        par = doc.add_paragraph()
        par.paragraph_format.space_after = Pt(0)
        par.paragraph_format.left_indent = Cm(0.3)
        shade(par, "F3F4F8", par=True)
        run = par.add_run(line if line else " ")
        run.font.name = "Consolas"
        run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        run.font.size = Pt(8)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def add_page_number_footer():
    par = sec.footer.paragraphs[0]
    par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = par.add_run("VTS — Báo cáo đồ án IT6027 — trang ")
    run.font.size = Pt(9)
    for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
        r = par.add_run()
        r.font.size = Pt(9)
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        r._r.append(el)


# ------------------------------------------------------------------ cover
for _ in range(5):
    doc.add_paragraph()
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("BÁO CÁO ĐỒ ÁN")
r.bold = True
r.font.size = Pt(26)
r.font.color.rgb = RGBColor(0x1F, 0x2F, 0x5F)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Hệ thống kiểm thử lỗ hổng (VTS) — Đề 7")
r.bold = True
r.font.size = Pt(18)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run("Môn học: IT6027 — Chính sách quản trị an ninh mạng").font.size = Pt(13)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run("Hệ thống học tập trong lab — chỉ quét mục tiêu thuộc scope đã xác nhận").italic = True
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run("Ngày hoàn thiện số liệu kiểm thử: 08/10/2026").font.size = Pt(11)
doc.add_page_break()
add_page_number_footer()

# ----------------------------------------------------------------- body
lines = MD.read_text(encoding="utf-8").splitlines()
i = 0
mermaid_idx = 0
skip_title = True
while i < len(lines):
    line = lines[i]
    stripped = line.strip()
    if stripped.startswith("```"):
        lang = stripped[3:].strip()
        j = i + 1
        buf = []
        while not lines[j].strip().startswith("```"):
            buf.append(lines[j])
            j += 1
        i = j + 1
        if lang == "mermaid":
            add_image(MERMAID_IMAGES[mermaid_idx])
            mermaid_idx += 1
        else:
            add_code(buf)
        continue
    if stripped.startswith("|"):
        rows = []
        while i < len(lines) and lines[i].strip().startswith("|"):
            cells = lines[i].strip().strip("|").split("|")
            rows.append(cells)
            i += 1
        add_table(rows)
        continue
    m = re.match(r"^!\[[^\]]*\]\(([^)]+)\)\s*$", stripped)
    if m:
        add_image(Path(m.group(1)).name)
        i += 1
        continue
    if stripped == "---" or not stripped:
        i += 1
        continue
    if stripped.startswith("# "):
        i += 1  # cover page carries the title
        continue
    if stripped.startswith("## "):
        if stripped.startswith("## 5."):
            pass
        doc.add_heading(stripped[3:].replace("`", ""), level=1)
        i += 1
        continue
    if stripped.startswith("### "):
        doc.add_heading(stripped[4:].replace("`", ""), level=2)
        i += 1
        # decomposition diagrams go right after the heading of 4.2's content
        continue
    if stripped.startswith("#### "):
        doc.add_heading(stripped[5:], level=3)
        i += 1
        continue
    if stripped.startswith(">"):
        par = doc.add_paragraph()
        par.paragraph_format.left_indent = Cm(0.6)
        add_inline(par, stripped.lstrip("> ").strip())
        for run in par.runs:
            run.italic = True
        i += 1
        continue
    if re.match(r"^[-*] ", stripped):
        par = doc.add_paragraph(style="List Bullet")
        par.paragraph_format.space_after = Pt(2)
        indent = len(line) - len(line.lstrip())
        if indent >= 2:
            par.paragraph_format.left_indent = Cm(1.4)
        add_inline(par, stripped[2:])
        i += 1
        continue
    m = re.match(r"^(\d+)\. (.*)$", stripped)
    if m:
        par = doc.add_paragraph(style="List Number")
        par.paragraph_format.space_after = Pt(2)
        add_inline(par, m.group(2))
        i += 1
        continue
    par = doc.add_paragraph()
    add_inline(par, stripped)
    i += 1
    # after the last paragraph of section 4.2 (before "## 5") add decomposition images
    nxt = next((l.strip() for l in lines[i:] if l.strip()), "")
    nxt2 = next((l.strip() for l in lines[i:] if l.strip() and l.strip() != "---"), "")
    if nxt2.startswith("## 5."):
        for name in EXTRA_AFTER_42:
            add_image(name)

assert mermaid_idx == len(MERMAID_IMAGES), mermaid_idx
doc.core_properties.title = "Báo cáo đồ án VTS — Đề 7 (IT6027)"
doc.core_properties.author = "Nhóm đồ án VTS"
doc.save(OUT)
print("saved", OUT, OUT.stat().st_size, "bytes")
