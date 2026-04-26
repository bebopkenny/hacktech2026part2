#!/usr/bin/env bash
# Tests /webhook/github locally. Backend must be running on :8000.
set -e

URL="http://localhost:8000/webhook/github"

# Pull secret from env, else from .env one dir up, else .env in CWD.
SECRET="${GITHUB_WEBHOOK_SECRET:-}"
if [ -z "$SECRET" ] && [ -f "../.env" ]; then
  SECRET=$(grep '^GITHUB_WEBHOOK_SECRET=' ../.env | cut -d= -f2- | tr -d '"' | tr -d '[:space:]')
fi
if [ -z "$SECRET" ] && [ -f ".env" ]; then
  SECRET=$(grep '^GITHUB_WEBHOOK_SECRET=' .env | cut -d= -f2- | tr -d '"' | tr -d '[:space:]')
fi
if [ -z "$SECRET" ]; then
  echo "GITHUB_WEBHOOK_SECRET is not set."
  echo "Generate one with: openssl rand -hex 32"
  echo "Add it to .env, restart the backend, then re-run this script."
  exit 1
fi
echo "Using secret prefix: ${SECRET:0:8}..."

hmac_sig() {
  echo -n "$1" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}'
}

echo ""
echo "Test 1: invalid signature should return 401"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: sha256=deadbeef" \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}')
if [ "$code" = "401" ]; then
  echo "  PASS - got 401"
else
  echo "  FAIL - got $code"
fi

echo ""
echo "Test 2: valid ping event should return pong"
PAYLOAD='{"zen":"hello"}'
SIG="sha256=$(hmac_sig "$PAYLOAD")"
resp=$(curl -s -X POST "$URL" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature-256: $SIG" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")
echo "  response: $resp"
if echo "$resp" | grep -q "pong"; then
  echo "  PASS"
else
  echo "  FAIL"
fi

echo ""
echo "Test 3: valid push event should kick off a scan (watch the dashboard!)"
PAYLOAD='{"repository":{"clone_url":"https://github.com/cr0hn/vulnerable-node.git"}}'
SIG="sha256=$(hmac_sig "$PAYLOAD")"
resp=$(curl -s -X POST "$URL" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: $SIG" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")
echo "  response: $resp"
if echo "$resp" | grep -q "scan_id"; then
  echo "  PASS - webhook triggered a scan"
else
  echo "  FAIL"
fi
