"""
FastAPI entry point.

Routes:
  POST /scan                  — kick off pipeline for a GitHub URL, returns {scan_id}
  GET  /scan/{scan_id}/status — poll for status: cloning|scanning|analyzing|complete|error
  GET  /findings/{scan_id}    — fetch results once complete
  GET  /health                — liveness probe for the deploy script and load balancers
  POST /webhook/github        — GitHub push event receiver (HMAC-verified)
  WS   /ws                    — live event stream: scan_started, semgrep_done,
                                finding_ready, scan_complete

In-memory store (scans dict) is fine for demo — no database needed.
Pipeline runs in a background threading.Thread so the POST returns immediately.
WebSocket broadcasts are scheduled on the FastAPI event loop (captured at
startup) so background threads can fan events out to connected clients.
"""
# ruff: noqa: E402 — load_dotenv must run before analyzer/backboard_client are
# imported, since those modules read env vars at import time.
import os

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

import asyncio
import logging
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import backboard_client
import snapshots
import webhooks
from analyzer import analyze_finding
from context import assemble_context
from models import ScanRequest
from scanner import clone_repo, run_semgrep

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
log = logging.getLogger("pipeline")
_K2_PARALLEL = int(os.getenv("K2_PARALLEL", "5"))


app = FastAPI(title="SentinelAI")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(webhooks.router)

# ── WebSocket connection manager ─────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)


manager = ConnectionManager()
_loop: asyncio.AbstractEventLoop | None = None


@app.on_event("startup")
async def _capture_loop() -> None:
    global _loop
    _loop = asyncio.get_event_loop()


def _broadcast_sync(msg: dict) -> None:
    """Schedule a broadcast from a background thread onto the main event loop."""
    if _loop is not None and manager.active:
        asyncio.run_coroutine_threadsafe(manager.broadcast(msg), _loop)


# ── In-memory scan store ──────────────────────────────────────────────────────

# scan_id → {status, progress, raw_count, confirmed_count, findings, error}
scans: dict[str, dict] = {}
_lock = threading.Lock()


def _new_scan() -> str:
    scan_id = uuid.uuid4().hex
    with _lock:
        scans[scan_id] = {
            "status": "cloning",
            "progress": None,
            "raw_count": 0,
            "confirmed_count": 0,
            "findings": [],
            "error": None,
        }
    return scan_id


def _update(scan_id: str, **fields) -> None:
    with _lock:
        scans[scan_id].update(fields)


def _analyze_one(repo_path: str, finding: dict, prior_context: str) -> tuple[dict | None, dict]:
    """Run context-assembly + K2 analysis for a single Semgrep finding.

    Returns (verdict_or_None, finding). Verdict is None if anything raises;
    finding is returned alongside so the caller can correlate after as_completed
    reorders results.
    """
    try:
        bundle = assemble_context(repo_path, finding)
        verdict = analyze_finding(bundle, prior_context=prior_context)
        return verdict, finding
    except Exception as e:
        log.warning("analyze_one failed for %s: %s", finding.get("check_id"), e)
        return None, finding


def _pipeline(scan_id: str, url: str, pat: str | None) -> None:
    repo_path: str | None = None
    try:
        log.info("[%s] starting pipeline for %s", scan_id, url)
        _broadcast_sync({"type": "scan_started"})

        log.info("[%s] cloning…", scan_id)
        repo_path = clone_repo(url, pat)
        log.info("[%s] cloned to %s", scan_id, repo_path)
        _update(scan_id, status="scanning")

        log.info("[%s] running semgrep…", scan_id)
        raw = run_semgrep(repo_path)
        total = len(raw)
        log.info("[%s] semgrep done: %d candidate findings", scan_id, total)
        _update(scan_id, status="analyzing", raw_count=total, progress=f"0/{total} findings")
        _broadcast_sync({"type": "semgrep_done", "count": total})

        # Pull prior-scan context from Backboard (no-op if BACKBOARD_API_KEY unset
        # or this is the first scan of this repo).
        prior_context = backboard_client.get_history_summary(url)
        # Structured prior severities (used for escalated_from detection).
        prior_snapshot = snapshots.load(url)

        # K2 calls run in parallel — biggest wall-clock win in the pipeline.
        # Each finding is one independent K2 round-trip; up to K2_PARALLEL run
        # concurrently. _update() is already lock-protected; confirmed.append()
        # happens only on the main thread (in the as_completed loop).
        confirmed: list[dict] = []
        done = 0
        with ThreadPoolExecutor(max_workers=_K2_PARALLEL) as ex:
            futures = [ex.submit(_analyze_one, repo_path, f, prior_context) for f in raw]
            for fut in as_completed(futures):
                verdict, finding = fut.result()
                done += 1

                if verdict and verdict.get("exploitable"):
                    # Strip the tmp clone prefix so paths are stable across scans
                    # (the tempdir name is random) and look clean in the UI.
                    finding_path = finding.get("path", "unknown")
                    if finding_path != "unknown" and repo_path:
                        try:
                            finding_path = os.path.relpath(finding_path, repo_path)
                        except ValueError:
                            pass
                    result = {
                        "rule_id": finding.get("check_id", "unknown"),
                        "file": finding_path,
                        "line": finding.get("start", {}).get("line", 0),
                        "matched_code": finding.get("extra", {}).get("lines", ""),
                        "exploitable": True,
                        "confidence": verdict.get("confidence", "low"),
                        "taint_path": verdict.get("taint_path"),
                        "auth_gap": verdict.get("auth_gap"),
                        "exploit_steps": verdict.get("exploit_steps", []),
                        "severity": verdict.get("severity", "low"),
                        "fix": verdict.get("fix", ""),
                    }
                    result["escalated_from"] = snapshots.escalation(prior_snapshot, result)
                    confirmed.append(result)
                    _broadcast_sync({
                        "type": "finding_ready",
                        "finding": result,
                        "index": done - 1,
                        "total": total,
                    })

                _update(
                    scan_id,
                    progress=f"{done}/{total} findings",
                    confirmed_count=len(confirmed),
                    findings=list(confirmed),
                )

        _update(
            scan_id,
            status="complete",
            confirmed_count=len(confirmed),
            findings=confirmed,
            progress=f"{total}/{total} findings",
        )
        _broadcast_sync({"type": "scan_complete", "raw_count": total})

        log.info("[%s] complete: %d/%d confirmed exploitable", scan_id, len(confirmed), total)
        # Persist this scan for next-scan diff (escalated_from) + Backboard memory.
        snapshots.save(url, confirmed)
        backboard_client.append_findings(url, confirmed)
    except Exception as e:
        log.exception("[%s] pipeline failed", scan_id)
        _update(scan_id, status="error", error=str(e))
        _broadcast_sync({"type": "scan_error", "error": str(e)})
    finally:
        if repo_path and os.path.isdir(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)


def _start_pipeline(url: str, pat: str | None) -> str:
    scan_id = _new_scan()
    threading.Thread(target=_pipeline, args=(scan_id, url, pat), daemon=True).start()
    return scan_id


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/scan")
def start_scan(req: ScanRequest) -> dict:
    scan_id = _start_pipeline(req.url, req.pat)

    # Fire-and-forget webhook registration so the response doesn't block on
    # GitHub's API. Skipped if PAT or env config is missing — registration is
    # a bonus, not a prerequisite for the scan.
    public_url = os.getenv("PUBLIC_WEBHOOK_URL")
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if req.pat and public_url and secret:
        threading.Thread(
            target=webhooks.register_webhook,
            args=(req.url, req.pat, public_url, secret),
            daemon=True,
        ).start()

    return {"scan_id": scan_id}


@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: str) -> dict:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "status": scan["status"],
        "progress": scan["progress"],
        "error": scan["error"],
    }


@app.get("/findings/{scan_id}")
def scan_findings(scan_id: str) -> dict:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "raw_count": scan["raw_count"],
        "confirmed_count": scan["confirmed_count"],
        "findings": scan["findings"],
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep connection alive; server only pushes
    except WebSocketDisconnect:
        manager.disconnect(websocket)
