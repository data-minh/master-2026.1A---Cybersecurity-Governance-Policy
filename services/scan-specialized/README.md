# Specialized Scanners & Template Management

Dò XSS phản chiếu, CRLF injection, S3 public listing (chỉ dò bằng marker, không khai thác) và quản lý template người dùng (Người 2 — B2+B3).

## API / hành vi
- Worker: nhận `scan.specialized_url`, phát `vuln.detected`.
- `GET /templates`, `GET /templates/{id}`, `POST /templates/validate` — mọi role đăng nhập.
- `POST /templates`, `DELETE /templates/{id}` — chỉ role `admin`.
- `POST /scan/xss|crlf|s3`.

## Ghi chú vận hành
Validate template chặn key nguy hiểm (`command`, `exec`, `shell`…), method ghi, regex ReDoS. Template người dùng lưu bền trong Redis (hash `vts:templates:user`); scan-engine đồng bộ lại định kỳ 5 s.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build scan-specialized
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
