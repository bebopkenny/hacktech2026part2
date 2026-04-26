#!/usr/bin/env bash
# Pull latest main and rebuild. Run on the Vultr box, or invoked by the
# deploy GitHub Action over SSH.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/sentinelai}"

cd "${APP_DIR}"
BRANCH="${BRANCH:-$(cat .branch 2>/dev/null || echo main)}"
git fetch --all --prune
git checkout "${BRANCH}"
git reset --hard "origin/${BRANCH}"

# If .env defines DOMAIN, bring up Caddy too (auto-HTTPS).
PROFILE_ARGS=()
if grep -qE '^\s*DOMAIN=\S' .env 2>/dev/null; then
  PROFILE_ARGS=(--profile tls)
fi

docker compose "${PROFILE_ARGS[@]}" up -d --build
docker image prune -f >/dev/null 2>&1 || true

# wait for /health to come back
for i in $(seq 1 30); do
  if curl -fsS http://localhost:8000/health >/dev/null; then
    echo "deploy ok"
    exit 0
  fi
  sleep 2
done
echo "health check failed after 60s"
docker compose logs --tail=80
exit 1
