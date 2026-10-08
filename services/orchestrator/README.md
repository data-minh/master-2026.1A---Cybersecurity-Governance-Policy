# Orchestrator / Workflow Engine

Điều phối pipeline Recon → Scan → Verification, là nơi duy nhất ghi trạng thái scan/stage/work (Người 3 — D2).

## API / hành vi
- `POST /scans` (header `Idempotency-Key`), `GET /scans`, `GET /scans/{id}`, `GET /scans/{id}/work`, `GET /scans/{id}/results?kind=`, `POST /scans/{id}/cancel`.
- `GET /scans/{id}/stream` — SSE snapshot đầy đủ, hỗ trợ `Last-Event-ID`.
- `GET /scans/{id}/report` — báo cáo tổng hợp (số tài sản/phát hiện/đã xác minh, phát hiện theo severity, trạng thái approval, stage); không chứa evidence.
- `GET /history?status=&target=&limit=&offset=` và `GET /history/{scan_id}` — lịch sử kiểm tra lưu bền trong SQLite (`HISTORY_DB_PATH`, mặc định `/data/history.db`); tiến trình nền lưu mọi scan đã kết thúc, không trùng lặp.
- `GET /pipeline/default`; `/healthz`, `/readyz`, `/metrics`.

## Ghi chú vận hành
Webhook tùy chọn khi scan kết thúc (`notify.py`): chỉ bật khi `WEBHOOK_URL` đặt và host nằm trong `WEBHOOK_ALLOWED_HOSTS`; chỉ gửi tóm tắt. Ledger Redis (`vts:scan:*`, `vts:work:*`, `vts:stage:*`), phát lệnh vào `vts.commands.<service>`, tiêu thụ `vts.bus`, retry 1/5/15 s, watchdog kỹ thuật 7200 s.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build orchestrator
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
