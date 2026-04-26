"""
FastAPI entry point.

Routes:
  POST /scan                  — kick off pipeline for a GitHub URL, returns {scan_id}
  GET  /scan/{scan_id}/status — poll for status: cloning|scanning|analyzing|complete|error
  GET  /findings/{scan_id}    — fetch results once complete
  GET  /health                — liveness probe for the deploy script and load balancers

In-memory store (scans dict) is fine for demo — no database needed.
Pipeline runs in a background threading.Thread so the POST returns immediately.
"""
import os
import shutil
import threading
import uuid

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
from fastapi.middleware.cors import CORSMiddleware

from analyzer import analyze_finding
from context import assemble_context
from models import ScanRequest
from scanner import clone_repo, run_semgrep

app = FastAPI(title="SentinelAI")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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


def _pipeline(scan_id: str, url: str, pat: str | None) -> None:
    repo_path: str | None = None
    try:
        repo_path = clone_repo(url, pat)
        _update(scan_id, status="scanning")

        raw = run_semgrep(repo_path)
        total = len(raw)
        _update(scan_id, status="analyzing", raw_count=total, progress=f"0/{total} findings")

        confirmed: list[dict] = []
        for i, finding in enumerate(raw, start=1):
            try:
                bundle = assemble_context(repo_path, finding)
                verdict = analyze_finding(bundle)
            except Exception:
                _update(scan_id, progress=f"{i}/{total} findings")
                continue

            if verdict.get("exploitable"):
                confirmed.append({
                    "rule_id": finding.get("check_id", "unknown"),
                    "file": finding.get("path", "unknown"),
                    "line": finding.get("start", {}).get("line", 0),
                    "matched_code": finding.get("extra", {}).get("lines", ""),
                    "exploitable": True,
                    "confidence": verdict.get("confidence", "low"),
                    "taint_path": verdict.get("taint_path"),
                    "auth_gap": verdict.get("auth_gap"),
                    "exploit_steps": verdict.get("exploit_steps", []),
                    "severity": verdict.get("severity", "low"),
                    "fix": verdict.get("fix", ""),
                })
            _update(
                scan_id,
                progress=f"{i}/{total} findings",
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
    except Exception as e:
        _update(scan_id, status="error", error=str(e))
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
