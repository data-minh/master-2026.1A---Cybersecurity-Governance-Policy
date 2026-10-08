# Recon — Port Scan & Content Fuzz

Quét top-N cổng TCP và dò đường dẫn phổ biến trên endpoint, có giới hạn đồng thời (Người 1 — A3+A4).

## API / hành vi
- Worker: nhận `recon.port_scan`, `recon.content_fuzz`; phát `asset.port.open`, `asset.path.found`.
- API thủ công: `POST /portscan`, `POST /fuzz`.

## Ghi chú vận hành
Giới hạn: `TOP_PORTS` (mặc định 100), `MAX_CONCURRENCY` (20), timeout kết nối 1,5 s. Kiểm scope tên miền trước khi chạy, và chỉ quét IP phân giải thuộc dải riêng/loopback/link-local hoặc IP đã nằm trong scope (ngược lại: `skipped=ip_not_in_scope`).

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build recon-portfuzz
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
