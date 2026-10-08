# API Gateway

Cửa trước duy nhất: định tuyến `/{service}/{path}` tới service phía sau và kiểm JWT tập trung (Người 3 — D1).

## API / hành vi
- Công khai (không token): `POST /scope-auth/auth/login`, `GET /scope-auth/scope/check`, `GET /healthz`, `GET /readyz` (sẵn sàng khi scope-auth sẵn sàng).
- Còn lại cần `Authorization: Bearer <jwt>`; header được chuyển nguyên vẹn để upstream tự kiểm vai trò.
- Không hỗ trợ SSE qua gateway; trình duyệt dùng dashboard trực tiếp.

## Ghi chú vận hành
Không sử dụng Redis. Biến: `SCOPE_SERVICE_URL`, `ORCHESTRATOR_URL`, `DASHBOARD_URL`, `VERIFICATION_URL`, `*_URL` của các worker.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build gateway
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
