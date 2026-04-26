"""
GitHub webhook receiver — auto-rescan on push events.

Flow:
  GitHub repo push → POST /webhook/github → HMAC verify → kick off pipeline.

The pipeline reuses _start_pipeline() from main.py, so a webhook-driven scan
broadcasts the same WS events (scan_started, semgrep_done, finding_ready,
scan_complete) as a manual scan. The frontend doesn't need to distinguish —
events stream and the dashboard updates live.

Security:
  - HMAC-SHA256 over the raw request body, compared to GitHub's
    X-Hub-Signature-256 header using constant-time comparison.
  - Secret comes from GITHUB_WEBHOOK_SECRET env var. Generate with
    `openssl rand -hex 32` and use the same value when registering the hook.

Limitations (handled in later steps):
  - No PAT is stored per-repo yet, so private repos will fail to clone on
    webhook-triggered rescans. Step 3 (registrar) will persist the PAT
    alongside the hook registration.
"""
import hashlib
import hmac
import json
import logging
import os
import re

import httpx
from fastapi import APIRouter, HTTPException, Request

log = logging.getLogger("webhooks")

router = APIRouter()

_GITHUB_API = "https://api.github.com"


def _verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """Constant-time HMAC-SHA256 verification of GitHub webhook payloads.

    GitHub sends the signature as 'sha256=<hex>' in X-Hub-Signature-256.
    Returns False on missing prefix, malformed hex, or non-matching digest.
    """
    if not signature_header.startswith("sha256="):
        return False
    expected = signature_header[len("sha256="):]
    computed = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected)


@router.post("/webhook/github")
async def github_webhook(request: Request) -> dict:
    """Receive a GitHub webhook event and trigger a rescan on push.

    Returns a no-op 200 for `ping` (delivered when the hook is created) and
    for non-push events. Returns 401 on bad signature, 503 if the secret is
    unset, 400 on malformed payload.
    """
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        # Surface as 503 rather than silently passing — operator misconfig.
        raise HTTPException(status_code=503, detail="GITHUB_WEBHOOK_SECRET not configured")

    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(body, signature, secret):
        raise HTTPException(status_code=401, detail="invalid signature")

    event = request.headers.get("X-GitHub-Event", "")
    delivery = request.headers.get("X-GitHub-Delivery", "?")

    if event == "ping":
        log.info("webhook ping (delivery=%s)", delivery)
        return {"ok": True, "msg": "pong"}

    if event != "push":
        log.info("webhook event=%s ignored (delivery=%s)", event, delivery)
        return {"ok": True, "msg": f"event {event} ignored"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON body") from None

    clone_url = payload.get("repository", {}).get("clone_url")
    if not clone_url:
        raise HTTPException(status_code=400, detail="missing repository.clone_url")

    # Late import dodges the circular: main.py imports this module to mount
    # the router, and we need _start_pipeline from main.
    from main import _start_pipeline
    scan_id = _start_pipeline(clone_url, None)
    log.info("webhook push → scan %s for %s (delivery=%s)", scan_id, clone_url, delivery)
    return {"ok": True, "scan_id": scan_id}


# ── Outbound: register a webhook on a GitHub repo ────────────────────────────


def _parse_repo(url: str) -> tuple[str, str] | None:
    """github.com/owner/repo → (owner, repo). Strips .git, /tree/, etc."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/.]+)", url)
    if not m:
        return None
    return m.group(1), m.group(2)


def register_webhook(repo_url: str, pat: str, public_url: str, secret: str) -> dict | None:
    """Register a push-event webhook on the given GitHub repo.

    Idempotent: lists existing hooks first and returns the existing entry if
    one already targets our URL. Otherwise creates a new hook.

    Returns the hook dict on success / already-registered, None on failure
    (bad PAT, missing admin:repo_hook scope, network error, unparseable URL).
    Failure is non-fatal — the scan still runs, just without auto-rescan on
    future pushes.
    """
    parsed = _parse_repo(repo_url)
    if not parsed:
        log.warning("register_webhook: couldn't parse owner/repo from %s", repo_url)
        return None
    owner, repo = parsed
    hook_url = public_url.rstrip("/") + "/webhook/github"

    headers = {
        "Authorization": f"token {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{_GITHUB_API}/repos/{owner}/{repo}/hooks", headers=headers)
            r.raise_for_status()
            for hook in r.json():
                if hook.get("config", {}).get("url") == hook_url:
                    log.info("webhook already registered on %s/%s (id=%s)",
                             owner, repo, hook.get("id"))
                    return hook

            r = c.post(
                f"{_GITHUB_API}/repos/{owner}/{repo}/hooks",
                headers=headers,
                json={
                    "name": "web",
                    "active": True,
                    "events": ["push"],
                    "config": {
                        "url": hook_url,
                        "content_type": "json",
                        "secret": secret,
                        "insecure_ssl": "0",
                    },
                },
            )
            r.raise_for_status()
            hook = r.json()
            log.info("webhook registered on %s/%s (id=%s)",
                     owner, repo, hook.get("id"))
            return hook
    except httpx.HTTPStatusError as e:
        log.warning("webhook registration failed (%d) on %s/%s: %s",
                    e.response.status_code, owner, repo, e.response.text[:200])
        return None
    except httpx.HTTPError as e:
        log.warning("webhook registration network error on %s/%s: %s",
                    owner, repo, e)
        return None
