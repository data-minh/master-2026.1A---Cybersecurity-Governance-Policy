#!/usr/bin/env bash
# Dựng môi trường chạy VTS trên máy ảo Ubuntu 24.04 (hoặc 22.04): cài Docker Engine + Compose v2.
# TRẠNG THÁI: chưa được kiểm thử trên máy ảo thật (môi trường đã kiểm thử: Windows 10 + Docker Desktop).
#
# Dùng:   sudo bash scripts/setup_vm.sh            # chỉ cài Docker
#         sudo bash scripts/setup_vm.sh --start    # cài Docker rồi khởi động VTS (profile demo)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Cần chạy bằng sudo/root." >&2
  exit 1
fi

START=0
[[ "${1:-}" == "--start" ]] && START=1

. /etc/os-release
if [[ "${ID}" != "ubuntu" ]]; then
  echo "Script này chỉ hỗ trợ Ubuntu (phát hiện: ${ID})." >&2
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl gnupg

install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

if [[ -n "${SUDO_USER:-}" ]]; then
  usermod -aG docker "${SUDO_USER}"
  echo "Đã thêm ${SUDO_USER} vào nhóm docker (đăng xuất/đăng nhập lại để có hiệu lực)."
fi

docker --version
docker compose version

if [[ $START -eq 1 ]]; then
  cd "$(dirname "$0")/.."
  [[ -f .env ]] || cp .env.example .env
  docker compose --profile demo up -d --build
  echo "Dashboard: http://127.0.0.1:8080  (đăng nhập operator/operator123 — chỉ lab)"
fi
