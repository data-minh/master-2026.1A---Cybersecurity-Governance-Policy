"""Swimlane activity diagram of the main flow (scan -> verify -> approval)."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon, Rectangle

OUT = Path(__file__).parent / "diagrams"
plt.rcParams["font.family"] = "DejaVu Sans"

fig, ax = plt.subplots(figsize=(15, 8.8))
ax.set_xlim(0, 16)
ax.set_ylim(0, 9.2)
ax.axis("off")

LANES = [("Người dùng / API", 0.1, 3.2), ("Recon", 3.3, 3.7), ("Scan", 7.0, 3.7),
         ("Verification và phê duyệt", 10.7, 5.2)]
for name, x, w in LANES:
    ax.add_patch(Rectangle((x, 0.1), w, 8.4, fill=False, ec="#6b7aa8", lw=1.2))
    ax.add_patch(Rectangle((x, 8.5), w, 0.55, fc="#dfe8ff", ec="#6b7aa8", lw=1.2))
    ax.text(x + w / 2, 8.78, name, ha="center", va="center", fontsize=10.5, weight="bold")

BOX, OK, BAD, DEC = "#eef3ff", "#e3f6e8", "#fde7e7", "#fff6e0"


def box(x, y, text, w=3.0, h=0.75, fc=BOX, rounded=False, fs=8.4):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.02,rounding_size=%s" % (0.3 if rounded else 0.06),
                                fc=fc, ec="#33406b", lw=1.2))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs)


def diamond(x, y, text, w=3.0, h=1.2):
    ax.add_patch(Polygon([(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)],
                         closed=True, fc=DEC, ec="#33406b", lw=1.2))
    ax.text(x, y, text, ha="center", va="center", fontsize=8.2)


def label(x, y, text):
    ax.text(x, y, text, fontsize=8, style="italic", ha="center", va="center",
            bbox=dict(fc="white", ec="none", pad=0.5))


def arrow(points, dashed=False):
    xs, ys = zip(*points)
    style = "--" if dashed else "-"
    ax.plot(xs[:-1], ys[:-1], color="#222", lw=1.1, ls=style, solid_capstyle="butt")
    ax.annotate("", xy=points[-1], xytext=points[-2],
                arrowprops=dict(arrowstyle="->", color="#222", lw=1.1, ls=style))


# ---------------- Lane 0
box(1.7, 8.0, "Bắt đầu: nhập target\n(Operator)", w=2.6, rounded=True, fc=OK)
diamond(1.7, 6.6, "Target nằm\ntrong scope?", w=2.9)
box(1.7, 4.8, "403 SCOPE_DENIED\n(kết thúc)", w=2.6, rounded=True, fc=BAD)
arrow([(1.7, 7.62), (1.7, 7.2)])
arrow([(1.7, 6.0), (1.7, 5.18)])
label(2.05, 5.6, "Không")

# ---------------- Lane 1: Recon
box(5.15, 6.6, "Tạo scan: queued → running\nđăng ký work gốc + lệnh Recon", w=3.1)
box(5.15, 5.5, "Recon bootstrap:\nsubdomain + OSINT", w=3.1)
box(5.15, 4.4, "Mỗi host: HTTP probe,\nport scan (top-N)", w=3.1)
box(5.15, 3.3, "Mỗi endpoint / URL page:\ncontent fuzz + đăng ký work Scan", w=3.1)
box(5.15, 2.0, "Chờ work còn lại,\nrồi kiểm tra lại", w=2.6)
box(5.15, 0.7, "Stage failed ⇒ scan failed,\nhủy work còn mở (kết thúc)", w=3.1, rounded=True, fc=BAD)
arrow([(3.15, 6.6), (3.6, 6.6)])
label(3.38, 6.88, "Có")
arrow([(5.15, 6.22), (5.15, 5.88)])
arrow([(5.15, 5.12), (5.15, 4.78)])
arrow([(5.15, 4.02), (5.15, 3.68)])
# failure branch (dashed): host work fails after 3 retries
arrow([(3.6, 4.4), (3.45, 4.4), (3.45, 0.7), (3.6, 0.7)], dashed=True)
label(3.45, 2.7, "work lỗi,\nhết 3 lần\nretry")

# ---------------- Lane 2: Scan
box(8.85, 6.6, "Scan (streaming): template engine\n+ specialized (XSS / CRLF / S3)", w=3.2)
diamond(8.85, 5.1, "Có finding\nhigh / critical?", w=3.0)
diamond(8.85, 2.0, "Mọi stage sealed, hết work mở,\nmọi approval resolved?", w=3.3, h=1.4)
box(8.85, 0.7, "Scan succeeded\n(snapshot cuối bất biến)", w=3.0, rounded=True, fc=OK)
arrow([(6.7, 3.3), (6.85, 3.3), (6.85, 6.6), (7.25, 6.6)])
label(6.85, 4.9, "streaming:\nScan chạy\nkhi Recon\ncòn mở")
arrow([(8.85, 6.22), (8.85, 5.7)])
arrow([(8.85, 4.5), (8.85, 2.7)])
label(9.15, 3.6, "Không")
arrow([(8.85, 1.3), (8.85, 1.08)])
label(9.15, 1.18, "Có")
arrow([(7.2, 2.0), (6.45, 2.0)])
label(6.82, 2.25, "Không")
arrow([(5.15, 1.62), (5.15, 1.4), (7.0, 1.4), (7.0, 1.7)], dashed=True)

# ---------------- Lane 3: Verification
box(13.3, 6.6, "Safe-verify: GET không phá hủy,\nkhông payload", w=3.1)
box(13.3, 5.5, "Tạo approval pending\n⇒ scan awaiting_approval", w=3.1)
diamond(13.3, 4.2, "Quyết định của\nngười có quyền", w=3.1, h=1.2)
box(11.95, 2.75, "Reject:\nhủy work execute\n(resolved)", w=1.7, h=0.85, fs=7.8)
box(13.7, 2.75, "Approve rồi\nexecute dry-run\n(yêu cầu riêng)", w=1.75, h=0.85, fs=7.8)
box(15.35, 2.75, "Quá hạn:\nscan timed_out\n(kết thúc)", w=1.15, h=0.85, rounded=True, fc=BAD, fs=7.2)
arrow([(10.35, 5.1), (11.0, 5.1), (11.0, 6.6), (11.75, 6.6)])
label(10.75, 5.35, "Có")
arrow([(13.3, 6.22), (13.3, 5.88)])
arrow([(13.3, 5.12), (13.3, 4.8)])
# decision outputs: bus below the diamond
ax.plot([11.95, 15.35], [3.35, 3.35], color="#222", lw=1.1)
ax.plot([13.3, 13.3], [3.6, 3.35], color="#222", lw=1.1)
for bx in (11.95, 13.7, 15.35):
    arrow([(bx, 3.35), (bx, 3.18)])
label(12.4, 3.5, "Reject")
label(14.05, 3.5, "Approve")
label(15.2, 3.5, "Quá hạn")
# Reject / Approve -> closing decision
ax.plot([11.95, 11.95], [2.32, 1.55], color="#222", lw=1.1)
ax.plot([13.7, 13.7], [2.32, 1.55], color="#222", lw=1.1)
ax.plot([11.95, 13.7], [1.55, 1.55], color="#222", lw=1.1)
arrow([(11.95, 1.55), (11.0, 1.55), (11.0, 2.0), (10.5, 2.0)])
label(12.4, 1.78, "kiểm tra điều kiện kết thúc")

fig.savefig(OUT / "hoat_dong.png", dpi=170, bbox_inches="tight", facecolor="white")
print("ok")
