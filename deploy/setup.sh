#!/usr/bin/env bash
# One-time setup for the Vultr VM. Idempotent — safe to re-run.
#
# Usage (on the Vultr box, as root):
#   curl -fsSL https://raw.githubusercontent.com/bebopkenny/hacktech2026part2/main/deploy/setup.sh | bash
#   # then: scp .env root@<vultr-ip>:/opt/sentinelai/.env
#   # then: cd /opt/sentinelai && docker compose up -d --build
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/bebopkenny/hacktech2026part2.git}"
APP_DIR="${APP_DIR:-/opt/sentinelai}"
BRANCH="${BRANCH:-main}"

echo ">>> apt update + install docker, compose plugin, git"
apt-get update
apt-get install -y ca-certificates curl gnupg git ufw

if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

systemctl enable --now docker

echo ">>> firewall: allow SSH, 8000, 80, 443"
ufw allow OpenSSH || true
ufw allow 8000/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
yes | ufw enable || true

echo ">>> clone or update repo at ${APP_DIR} (branch: ${BRANCH})"
if [ -d "${APP_DIR}/.git" ]; then
  git -C "${APP_DIR}" fetch --all --prune
  git -C "${APP_DIR}" checkout "${BRANCH}"
  git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
else
  git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
fi
# Persist the chosen branch so redeploy.sh tracks the same one.
echo "${BRANCH}" > "${APP_DIR}/.branch"

if [ ! -f "${APP_DIR}/.env" ]; then
  echo ""
  echo "!! Missing ${APP_DIR}/.env — copy it from your laptop:"
  echo "   scp .env root@<vultr-ip>:${APP_DIR}/.env"
  echo "   It must contain ANTHROPIC_API_KEY and WEBHOOK_SECRET."
  exit 1
fi

echo ">>> docker compose up"
cd "${APP_DIR}"
PROFILE_ARGS=()
if grep -qE '^\s*DOMAIN=\S' .env 2>/dev/null; then
  PROFILE_ARGS=(--profile tls)
  echo "    DOMAIN set — bringing up Caddy for HTTPS"
fi
docker compose "${PROFILE_ARGS[@]}" up -d --build

IP=$(hostname -I | awk '{print $1}')
echo ""
echo "SentinelAI running on http://${IP}:8000"
echo "  health:  curl http://${IP}:8000/health"
echo "  logs:    docker compose -f ${APP_DIR}/docker-compose.yml logs -f"
