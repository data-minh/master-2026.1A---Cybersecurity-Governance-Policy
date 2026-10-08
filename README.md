# VTS — Hệ thống kiểm thử lỗ hổng (Đề 7, IT6027)

Hệ thống microservice (FastAPI + Redis Streams) thực hiện pipeline **Recon → Scan → Verification** có cổng **phê duyệt thủ công**, và chỉ hoạt động trong **scope đã xác nhận**. Dùng cho mục đích học tập trong lab; mục tiêu demo là `vuln-target` chạy nội bộ.

Tài liệu: [báo cáo nộp bài](docs/BaoCao_NopBai.md) · [chi tiết lifecycle](docs/BaoCao.md) · README từng service trong `services/<tên>/README.md`.

## Yêu cầu
- Docker Engine ≥ 24 và Docker Compose v2 (đã kiểm thử: Docker 28.4.0, Compose 2.39.2 trên Windows 10). Máy ảo Linux có Docker là đủ.
- Để chạy test: Python 3.12 (đã kiểm thử 3.12.10).

## Chạy nhanh (demo)
```bash
cp .env.example .env            # chỉnh JWT_SECRET (>= 32 ký tự) nếu không phải lab cô lập
docker compose --profile demo up -d --build
```
| Địa chỉ (chỉ `127.0.0.1`) | Dịch vụ |
|---|---|
| http://127.0.0.1:8080 | Dashboard (giao diện chính) |
| http://127.0.0.1:8000/docs | Gateway |
| http://127.0.0.1:8001/docs | Scope & Auth (OpenAPI) |
| http://127.0.0.1:8002/docs | Orchestrator (OpenAPI) |
| http://127.0.0.1:8023/docs | Verification & Approval (OpenAPI) |
| http://127.0.0.1:8090 | vuln-target (mục tiêu demo) |

Mỗi service có `/docs`, `/openapi.json`, `/healthz`, `/readyz`, `/metrics` (gateway có `/healthz`, `/readyz`).

Báo cáo tổng hợp theo scan: `GET /scans/{id}/report` (orchestrator) hoặc `GET /dashboard/scans/{id}/report` (đã đăng nhập). Webhook khi scan kết thúc: mặc định **tắt**; bật bằng `WEBHOOK_URL` và `WEBHOOK_ALLOWED_HOSTS` trong `.env` (chỉ gửi tóm tắt, không gửi bằng chứng).

Máy ảo/offline: xem `scripts/setup_vm.sh` và `scripts/export_images.sh` (báo cáo §3.5).

Tài khoản **lab** (đổi trước khi dùng ở nơi khác): `operator/operator123`, `approver/approver123`, `admin/admin123`.

| Vai trò | Quyền |
|---|---|
| `operator` | Khởi chạy, theo dõi, hủy scan; xem phát hiện và lịch sử. Không thấy mục Phạm vi. |
| `approver` | Như operator, cộng phê duyệt/từ chối/thực thi dry-run; xem (không sửa) Phạm vi. |
| `admin` | Như approver, cộng thêm/xóa mục tiêu trong Phạm vi và quản lý Template. |

Giao diện có chế độ sáng/tối (theo hệ điều hành, nút ở thanh bên để đổi và nhớ lựa chọn). Lịch sử kiểm tra lưu trong SQLite (volume `vts-history-data`), không hết hạn như dữ liệu Redis.

## Kịch bản demo
1. Mở http://127.0.0.1:8080, đăng nhập `approver`.
2. Mục tiêu `vuln-target` (đã có trong scope), chế độ *Toàn bộ* → **Bắt đầu quét**.
3. Quan sát 3 stage chạy chồng nhau; khi scan chuyển *Chờ phê duyệt*, bấm **Phê duyệt** rồi **Thực thi (dry-run)** (hoặc **Từ chối**).
4. Scan chuyển *Thành công*; xem danh sách phát hiện và nút **Xem trước** (GET đọc-chỉ, kiểm scope).
5. Mục **Lịch sử kiểm tra** hiện mọi phiên đã kết thúc; bấm một dòng để xem chi tiết và xuất CSV/JSON.
6. Đăng nhập `admin` để thêm/xóa mục tiêu trong **Phạm vi** và thêm/xóa template trong **Template**.

Tắt stack (giữ dữ liệu): `docker compose --profile demo down` — **không** dùng `-v`.

## Kiểm thử
```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .\.venv\Scripts\activate
pip install -r common/requirements.txt -r requirements-dev.txt && pip install -e common
playwright install chromium                    # chỉ cho test giao diện
```
Chạy stack cô lập theo `docs/BaoCao.md` §8.2 (cổng 18xxx, nguồn ngoài tắt); trên bash có thể nạp biến bằng `. scripts/test_stack_env.sh`. Rồi:
```bash
export VTS_TEST_REDIS_URL=redis://127.0.0.1:16379/15
python -m pytest common/tests services/gateway/tests services/scan-engine/tests services/orchestrator/tests \
  services/dashboard/tests services/verification/tests tests/test_lifecycle_docs.py tests/integration -q
python scripts/e2e_test.py     # cần VTS_*_URL và RECON_EXTERNAL_SOURCES_ENABLED=false
python scripts/measure.py
```
Kết quả đã ghi nhận: 191 test pass, 13 test giao diện (Playwright) pass; E2E PASS (scan thành công ở revision 58, 12 work, 2 approval).

## Cấu trúc
```
common/vts_common/   thư viện dùng chung: event v1, worker, scope client, JWT, config
services/            gateway, scope-auth, orchestrator, dashboard, recon-*, scan-*, verification, vuln-target
scripts/             e2e_test.py, measure.py, migrate_legacy_events.py, setup_vm.sh (Ubuntu + Docker), export_images.sh (docker save/load offline)
tests/               integration, browser (Playwright)
docs/                BaoCao.md (lifecycle), BaoCao_NopBai.md (báo cáo nộp), PROMPT_HOAN_THIEN.md
build/               sinh báo cáo Word: make_docx.py, render_mermaid.py, draw_usecase.py, draw_activity.py
BaoCao_VTS.docx      báo cáo nộp bài (Word)
```

## Lưu ý an toàn
Chỉ kiểm thử mục tiêu bạn được phép. Không bật `RECON_EXTERNAL_SOURCES_ENABLED` cho mục tiêu thật khi chưa có ủy quyền. Đây là hệ thống lab: Redis chưa có ACL/TLS, secret và tài khoản là mặc định.
