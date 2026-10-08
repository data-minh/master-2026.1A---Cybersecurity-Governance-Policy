# vuln-target (chỉ demo)

Cửa hàng kính giả cố ý lộ file cấu hình để pipeline có thứ phát hiện. **Không triển khai ở môi trường thật.**

## API / hành vi
- Lỗi cố ý: `/.env`, `/.git/config`, `/phpinfo.php`, `/actuator/health`, `/?q=` (XSS phản chiếu).
- Chỉ chạy với profile `demo`: `docker compose --profile demo up -d`.

## Ghi chú vận hành
Không phụ thuộc Redis hay `common`. Đã có sẵn trong scope mẫu.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build vuln-target
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`.
