# Dashboard (BFF + UI)

Giao diện một trang và lớp BFF: đăng nhập theo người dùng, proxy tới orchestrator/verification/scope-auth (Người 3 — D3+D5).

## API / hành vi
- `POST /dashboard/login|logout`, `GET /dashboard/me`.
- `GET /dashboard/scans[/{id}[/work|/results|/report|/stream]]`, `POST /dashboard/scan`.
- `GET /dashboard/approvals`, `POST /dashboard/approvals/{id}/{approve|reject|execute}`.
- `GET /dashboard/scope` (admin, approver); `POST|DELETE /dashboard/scope` (admin).
- `GET|POST /dashboard/templates`, `POST /dashboard/templates/validate`, `DELETE /dashboard/templates/{id}` (chỉ admin).
- `GET /dashboard/history`, `GET /dashboard/history/{scan_id}` (mọi vai trò).
- `GET /dashboard/preview?url=`.
- Mọi POST/DELETE cần header `X-VTS-CSRF: 1`.

## Ghi chú vận hành
Không lưu trạng thái; JWT nằm trong cookie `vts_session` (HttpOnly, SameSite=Strict). UI dùng SSE và polling dự phòng, bỏ snapshot có `revision` cũ.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build dashboard
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
