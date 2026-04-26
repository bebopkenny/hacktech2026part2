"""
FastAPI entry point.

Routes:
  POST /scan                  — kick off pipeline for a GitHub URL, returns {scan_id}
  GET  /scan/{scan_id}/status — poll for status: cloning|scanning|analyzing|complete|error
  GET  /findings/{scan_id}    — fetch results once complete
  POST /webhook/github        — receives GitHub push events, validates HMAC, triggers pipeline

In-memory store (scans dict) is fine for demo — no database needed.
Pipeline runs in a background threading.Thread so the POST returns immediately.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SentinelAI")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# scan_id → {status, progress, raw_count, confirmed_count, findings, error?}
scans: dict[str, dict] = {}

# TODO: implement routes and pipeline (_pipeline runs in threading.Thread)
