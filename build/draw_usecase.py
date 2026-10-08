"""UML use-case diagrams (overview + decompositions) drawn with matplotlib."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, Rectangle

OUT = Path(__file__).parent / "diagrams"
plt.rcParams["font.family"] = "DejaVu Sans"


def actor(ax, x, y, name):
    ax.add_patch(plt.Circle((x, y + 0.55), 0.18, fill=False, lw=1.6))
    ax.plot([x, x], [y + 0.37, y - 0.1], "k", lw=1.6)
    ax.plot([x - 0.3, x + 0.3], [y + 0.25, y + 0.25], "k", lw=1.6)
    ax.plot([x, x - 0.25], [y - 0.1, y - 0.55], "k", lw=1.6)
    ax.plot([x, x + 0.25], [y - 0.1, y - 0.55], "k", lw=1.6)
    ax.text(x, y - 0.75, name, ha="center", va="top", fontsize=10, weight="bold")


def uc(ax, x, y, text, w=3.0, h=0.9, fc="#eef3ff"):
    ax.add_patch(Ellipse((x, y), w, h, fc=fc, ec="#33406b", lw=1.3))
    ax.text(x, y, text, ha="center", va="center", fontsize=8.6)
    return (x, y, w, h)


def link(ax, a, b, dashed=False):
    ax.add_patch(
        FancyArrowPatch(
            a, b,
            arrowstyle="->" if dashed else "-",
            linestyle="--" if dashed else "-",
            mutation_scale=11, lw=1.0, color="#222", shrinkA=0, shrinkB=0,
        )
    )


def note(ax, x, y, text):
    ax.text(x, y, text, fontsize=7.5, style="italic", ha="left",
            bbox=dict(fc="white", ec="none", pad=0.5))


# ---------------------------------------------------------------- overview
fig, ax = plt.subplots(figsize=(12.5, 9.6))
ax.set_xlim(0, 13)
ax.set_ylim(-0.2, 9.6)
ax.axis("off")
ax.add_patch(Rectangle((2.5, -0.1), 8.0, 9.4, fill=False, lw=1.8, ec="#33406b"))
ax.text(6.5, 9.0, "Hệ thống VTS", ha="center", fontsize=12, weight="bold")

left = [
    ("UC1", 8.3, "UC1  Đăng nhập"),
    ("UC3", 7.4, "UC3  Khởi chạy phiên quét"),
    ("UC4", 6.5, "UC4  Theo dõi tiến độ (dashboard, SSE)"),
    ("UC5", 5.6, "UC5  Xem phát hiện, xem trước bằng chứng"),
    ("UC12", 4.7, "UC12  Xem lịch sử kiểm tra và kết quả"),
    ("UC8", 3.8, "UC8  Hủy phiên quét"),
    ("UC6", 2.7, "UC6  Phê duyệt / từ chối / thực thi dry-run"),
    ("UC2", 1.7, "UC2  Phạm vi: approver xem, admin thêm/xóa"),
    ("UC7", 0.7, "UC7  Quản lý template trên dashboard (admin)"),
]
boxes = {k: uc(ax, 4.9, y, t, w=4.7, h=0.72) for k, y, t in left}
boxes["UC9"] = uc(ax, 9.0, 6.7, "UC9  Thu thập tài sản\n(Recon)", w=2.8, h=0.9, fc="#eefaf0")
boxes["UC10"] = uc(ax, 9.0, 5.0, "UC10  Dò lỗ hổng\n(Scan)", w=2.8, h=0.9, fc="#eefaf0")
boxes["UC11"] = uc(ax, 9.0, 3.3, "UC11  Xác minh an toàn\n(Verification)", w=2.8, h=0.9, fc="#eefaf0")
boxes["UC13"] = uc(ax, 9.0, 1.5, "UC13  Lưu lịch sử tự động\n(SQLite)", w=2.8, h=0.9, fc="#eefaf0")

actor(ax, 1.1, 5.6, "Operator")
actor(ax, 1.1, 3.1, "Approver")
actor(ax, 1.1, 0.5, "Admin")
actor(ax, 11.9, 3.8, "Hệ thống\n(tự động)")


def lx(k):
    b = boxes[k]
    return (b[0] - b[2] / 2, b[1])


def rx(k):
    b = boxes[k]
    return (b[0] + b[2] / 2, b[1])


for k in ("UC1", "UC3", "UC4", "UC5", "UC12", "UC8"):
    link(ax, (1.45, 6.0), lx(k))
link(ax, (1.45, 3.5), lx("UC6"))
link(ax, (1.45, 3.5), lx("UC2"))
link(ax, (1.45, 0.9), lx("UC7"))
link(ax, (1.45, 0.9), lx("UC2"))
# Kế thừa quyền: Admin -> Approver -> Operator
for a, b in (((1.1, 1.25), (1.1, 2.1)), ((1.1, 3.95), (1.1, 4.6))):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=14, lw=1.2,
                                 color="#444", shrinkA=0, shrinkB=0))
ax.text(0.1, 1.6, "kế thừa\nquyền", fontsize=7, style="italic")
ax.text(0.1, 4.1, "kế thừa\nquyền", fontsize=7, style="italic")
for k in ("UC9", "UC10", "UC11", "UC13"):
    link(ax, (11.55, 4.1), rx(k))
link(ax, (7.15, 7.2), (7.6, 6.95), dashed=True)
note(ax, 7.2, 7.5, "«include»")
link(ax, (9.0, 6.25), (9.0, 5.45), dashed=True)
link(ax, (9.0, 4.55), (9.0, 3.75), dashed=True)
note(ax, 9.1, 5.75, "«dẫn tới»")
note(ax, 9.1, 4.05, "«dẫn tới»")
link(ax, (8.0, 3.0), (7.25, 2.75), dashed=True)
note(ax, 7.9, 2.35, "«dẫn tới» phê duyệt")
fig.savefig(OUT / "usecase_tong_quan.png", dpi=170, bbox_inches="tight", facecolor="white")
plt.close(fig)


# ----------------------------------------------------------- decomposition
def decomp(title, parent, children, fname):
    n = len(children)
    height = 1.5 + 0.8 * n
    fig, ax = plt.subplots(figsize=(11, height))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, height)
    ax.axis("off")
    ytop = 0.9 + 0.8 * n
    ymid = (ytop + (ytop - 0.8 * (n - 1))) / 2
    uc(ax, 2.2, ymid, parent, w=3.4, h=1.2, fc="#dfe8ff")
    for i, c in enumerate(children):
        y = ytop - 0.8 * i
        e = uc(ax, 7.9, y, c, w=5.4, h=0.62, fc="#fff6e6")
        link(ax, (e[0] - e[2] / 2, y), (3.9, ymid), dashed=True)
    ax.text(5.5, height - 0.15, title, ha="center", fontsize=10.5, weight="bold")
    fig.savefig(OUT / fname, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)


decomp("Phân rã UC2 — Phạm vi được phép (approver xem, admin sửa)", "UC2\nPhạm vi",
       ["UC2.1  Xem danh sách (approver, admin; operator không thấy)",
        "UC2.2  Thêm mục tiêu (chỉ admin) + xác nhận được phép",
        "UC2.3  Xóa mục tiêu (chỉ admin, có hộp xác nhận)",
        "UC2.4  Kiểm tra mục tiêu GET /scope/check (nội bộ)"],
       "usecase_uc2.png")
decomp("Phân rã UC3 — Khởi chạy phiên quét", "UC3\nKhởi chạy phiên quét",
       ["UC3.1  Chọn chế độ: full / recon / recon-passive",
        "UC3.2  Chọn thực thi: sequential / parallel",
        "UC3.3  Kiểm tra scope trước khi tạo (ngoài scope: 403)",
        "UC3.4  Idempotency-Key: gửi lại cùng key trả cùng scan"],
       "usecase_uc3.png")
decomp("Phân rã UC6 — Phê duyệt và thực thi có kiểm soát", "UC6\nPhê duyệt / thực thi",
       ["UC6.1  Phê duyệt (approve) — chưa thực thi",
        "UC6.2  Từ chối (reject) — hủy work execute đang chờ",
        "UC6.3  Thực thi dry-run — chỉ sau approve, role approver/admin",
        "UC6.4  Quá hạn quyết định: scan timed_out"],
       "usecase_uc6.png")
decomp("Phân rã UC7 — Quản lý template trên dashboard (chỉ admin)", "UC7\nQuản lý template",
       ["UC7.1  Thêm template (soạn YAML, chèn mẫu)",
        "UC7.2  Kiểm tra (validate) trước khi lưu",
        "UC7.3  Xem danh sách và xóa (có hộp xác nhận)",
        "UC7.4  Hệ thống chặn: key nguy hiểm, method ghi, regex ReDoS"],
       "usecase_uc7.png")
decomp("Phân rã UC12 — Lịch sử kiểm tra (mọi vai trò)", "UC12\nLịch sử kiểm tra",
       ["UC12.1  Lọc theo mục tiêu và kết quả, phân trang",
        "UC12.2  Xem chi tiết: giai đoạn, phát hiện, phê duyệt, người chạy",
        "UC12.3  Xuất CSV phát hiện / tải JSON",
        "UC12.4  Lưu tự động mọi phiên đã kết thúc (kể cả hủy, hết hạn)"],
       "usecase_uc12.png")
print("done")
