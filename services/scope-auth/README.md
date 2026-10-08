# Scope & Auth

Cấp JWT, quản lý danh sách scope và trả lời `GET /scope/check` — kiểm soát an toàn trung tâm (Người 3 — D1+D4).

## API / hành vi
- `POST /auth/login` → `{access_token, role}`.
- `GET /scope/check?target=` → `{allowed, matched_rule}` (khớp domain, `*.domain`, CIDR).
- `GET /scope` — chỉ role `admin` và `approver` (operator nhận 403).
- `POST /scope`, `DELETE /scope/{id}` — chỉ role `admin`.

## Ghi chú vận hành
Scope lưu bền trong Redis (`vts:scope:*`). Lần đầu nạp 5 luật mẫu (gồm `vuln-target`). Lỗi store ⇒ HTTP 500 ⇒ client coi là không khả dụng, không bao giờ coi là cho phép.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build scope-auth
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
