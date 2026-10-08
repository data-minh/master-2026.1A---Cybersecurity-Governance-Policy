# Recon — Subdomain & OSINT

Phát hiện subdomain (wordlist + DNS, tùy chọn crt.sh) và thu thập OSINT công khai (email, title) (Người 1 — A1+A6).

## API / hành vi
- Worker: nhận `recon.bootstrap`, phát `asset.subdomain.discovered`, `asset.osint.collected`.
- API thủ công (cần JWT): `POST /discover`.
- `RECON_EXTERNAL_SOURCES_ENABLED=false` tắt crt.sh.

## Ghi chú vận hành
Kiểm `scope/check` trước mỗi host; host ngoài scope bị bỏ qua. Dùng stream `vts.commands.recon-subdomain`.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build recon-subdomain
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
