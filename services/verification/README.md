# Verification & Approval

Xác minh an toàn finding mức high/critical (GET không payload) và quản lý phê duyệt thủ công (Người 2 — C1+C2).

## API / hành vi
- Worker: `verification.safe_verify` ⇒ `vuln.verified` + `approval.requested`; `verification.execute` ⇒ `approval.executed` (dry-run).
- `GET /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/approve|reject|execute` (cần `Idempotency-Key`; role `approver`/`admin`).
- `GET /preview?url=` — đọc-chỉ, kiểm scope từng hop.

## Ghi chú vận hành
Máy trạng thái: `pending → approved → executing → executed` (hoặc `rejected`, `timed_out`, `execution_failed`). `execute` khi chưa `approved` ⇒ 409. Redis CAS đảm bảo một hành động thắng. `DRY_RUN=true`.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build verification
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
