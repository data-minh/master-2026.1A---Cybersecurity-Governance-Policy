# Recon — HTTP Probe & URL Harvest

Thăm dò host còn sống (status, title, tech, redirect) và thu thập URL (crawl HTML, tùy chọn Wayback); phân loại URL theo phần mở rộng (Người 1 — A2+A5).

## API / hành vi
- Worker: nhận `recon.http_probe_and_harvest`, phát `asset.endpoint.alive`, `asset.url.collected`.
- API thủ công: `POST /probe`.

## Ghi chú vận hành
HTTP qua `scoped_http_client` (kiểm scope từng hop redirect); URL ngoài scope bị lọc. Wayback tắt khi `RECON_EXTERNAL_SOURCES_ENABLED=false`.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build recon-httpprobe
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
