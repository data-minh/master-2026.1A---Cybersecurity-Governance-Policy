#!/usr/bin/env bash
# Đóng gói / nạp image VTS để chạy offline (không cần build lại, không cần Internet).
#
#   bash scripts/export_images.sh save [vts-images.tar]   # trên máy đã build
#   bash scripts/export_images.sh load [vts-images.tar]   # trên máy đích (đã có Docker)
#
# Sau khi nạp:  docker compose --profile demo up -d --no-build
set -euo pipefail

IMAGES=(
  vts/gateway:1.0.0 vts/scope-auth:1.0.0 vts/orchestrator:1.0.0 vts/dashboard:1.0.0
  vts/recon-subdomain:1.0.0 vts/recon-httpprobe:1.0.0 vts/recon-portfuzz:1.0.0
  vts/scan-engine:1.0.0 vts/scan-specialized:1.0.0 vts/verification:1.0.0
  vts/vuln-target:1.0.0 redis:7-alpine
)

cmd="${1:-}"
file="${2:-vts-images.tar}"

case "$cmd" in
  save)
    docker save -o "$file" "${IMAGES[@]}"
    ls -lh "$file"
    ;;
  load)
    docker load -i "$file"
    ;;
  *)
    echo "Dùng: $0 save|load [file.tar]" >&2
    exit 1
    ;;
esac
