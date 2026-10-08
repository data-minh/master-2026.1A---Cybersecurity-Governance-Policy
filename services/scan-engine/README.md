# Scan Engine (YAML template engine)

Engine tự viết đọc template YAML kiểu Nuclei, thực thi request, áp matcher `status/word/regex/json` và extractor (Người 2 — B1).

## API / hành vi
- Worker: nhận `scan.template_url`, phát `vuln.detected`.
- `GET /templates`, `POST /templates/reload`, `POST /scan`.
- 5 template mẫu trong `templates/`: env-file, git-config, phpinfo, actuator, directory-listing.
- Unit test: `services/scan-engine/tests`.

## Ghi chú vận hành
Template do người dùng (admin) đăng ký được nạp từ Redis (`vts:templates:user`) mỗi 5 s và sau khi khởi động lại; template file trong `templates/` không bị ảnh hưởng. Template chỉ dùng method `GET/HEAD/OPTIONS`; regex bị giới hạn độ dài và kiểm ReDoS; thân phản hồi tối đa 512 KB cho mỗi matcher.

## Chạy
```bash
# từ thư mục gốc repo
docker compose --profile demo up -d --build scan-engine
```
Tài liệu OpenAPI: `http://127.0.0.1:<cổng>/docs` (xem bảng cổng trong README gốc). Kiểm tra: `/healthz`, `/readyz`, `/metrics`.
