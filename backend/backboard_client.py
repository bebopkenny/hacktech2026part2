"""
Backboard integration — persistent per-repo memory layer.

Architecture:
  - One Backboard assistant + thread per GitHub repo URL.
  - Mapping {repo_url: (assistant_id, thread_id)} persisted to a JSON file
    so it survives container restarts. Thread access is locked.

Per-scan flow:
  - get_history_summary(repo_url)  → ask Backboard for prior-finding context.
  - K2 does its per-finding reasoning (in analyzer.py), prior_context injected.
  - append_findings(repo_url, findings) → write this scan's results to the
    thread with memory=Auto so facts persist for the next scan.

Backboard outages are non-fatal: every function returns "" / None and logs
a warning. The K2 path keeps working without memory.

Docs: https://docs.backboard.io
"""
import json
import logging
import os
import threading
from pathlib import Path

import httpx

log = logging.getLogger("backboard")

_BASE = os.getenv("BACKBOARD_BASE_URL", "https://app.backboard.io/api")
_MODEL = os.getenv("BACKBOARD_MODEL", "gpt-4o-mini")
_MAP_PATH = Path(os.getenv("BACKBOARD_MAP_PATH", "/tmp/sentinelai/backboard_repos.json"))
_TIMEOUT = 60.0
_lock = threading.Lock()

_SYSTEM_PROMPT = (
    "You are an archivist for security scans of a single GitHub repository. "
    "You receive lists of findings from each scan and answer questions about "
    "the repository's security history.\n\n"
    "When asked to summarize prior findings: list each one with its rule_id, "
    "file:line, severity, and exploitability verdict. If this is the first "
    "scan, reply with exactly: 'No prior scans.'\n\n"
    "When new findings are appended, acknowledge them briefly and let the "
    "memory layer extract facts automatically."
)


def is_enabled() -> bool:
    return bool(os.getenv("BACKBOARD_API_KEY"))


def _headers() -> dict:
    return {"X-API-Key": os.environ["BACKBOARD_API_KEY"], "Content-Type": "application/json"}


def _load_map() -> dict:
    if not _MAP_PATH.exists():
        return {}
    try:
        return json.loads(_MAP_PATH.read_text())
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not read %s: %s", _MAP_PATH, e)
        return {}


def _save_map(m: dict) -> None:
    _MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    _MAP_PATH.write_text(json.dumps(m, indent=2))


def _get_or_create_for_repo(repo_url: str) -> tuple[str, str] | None:
    """Returns (assistant_id, thread_id) for this repo, creating them if absent.

    Returns None on Backboard API failure — callers must handle.
    """
    with _lock:
        m = _load_map()
        if repo_url in m:
            e = m[repo_url]
            return e["assistant_id"], e["thread_id"]

        try:
            with httpx.Client(timeout=_TIMEOUT) as c:
                r = c.post(
                    f"{_BASE}/assistants",
                    headers=_headers(),
                    json={
                        "name": f"SentinelAI: {repo_url}",
                        "system_prompt": _SYSTEM_PROMPT,
                        "model": _MODEL,
                    },
                )
                r.raise_for_status()
                assistant_id = r.json().get("assistant_id") or r.json().get("id")
                if not assistant_id:
                    log.warning("Backboard returned no assistant_id: %r", r.json())
                    return None

                r = c.post(
                    f"{_BASE}/assistants/{assistant_id}/threads",
                    headers=_headers(),
                    json={},
                )
                r.raise_for_status()
                thread_id = r.json().get("thread_id") or r.json().get("id")
                if not thread_id:
                    log.warning("Backboard returned no thread_id: %r", r.json())
                    return None
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.warning("Backboard create failed for %s: %s", repo_url, e)
            return None

        m[repo_url] = {"assistant_id": assistant_id, "thread_id": thread_id}
        _save_map(m)
        log.info("Backboard registered repo %s → thread %s", repo_url, thread_id)
        return assistant_id, thread_id


def get_history_summary(repo_url: str) -> str:
    """Ask Backboard to summarize prior findings for this repo.

    Returns the assistant's reply text, or "" if Backboard is disabled, the
    repo is new (assistant says 'No prior scans.'), or any call fails.
    """
    if not is_enabled():
        return ""
    pair = _get_or_create_for_repo(repo_url)
    if not pair:
        return ""
    _, thread_id = pair

    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(
                f"{_BASE}/threads/{thread_id}/messages",
                headers=_headers(),
                json={
                    "content": (
                        "Summarize the security findings from prior scans of this "
                        "repository, if any. List each with rule_id, file:line, "
                        "severity, and exploitability verdict. If there are no prior "
                        "scans, reply with exactly: 'No prior scans.'"
                    ),
                    "stream": False,
                    "memory": "Readonly",
                },
            )
            r.raise_for_status()
            text = (r.json().get("content") or "").strip()
    except (httpx.HTTPError, KeyError, ValueError) as e:
        log.warning("Backboard get_history failed for %s: %s", repo_url, e)
        return ""

    if text == "No prior scans." or not text:
        return ""
    return text


def append_findings(repo_url: str, findings: list[dict]) -> None:
    """Write this scan's confirmed findings to the repo's thread with memory=Auto.

    No-op on disabled / failure / empty findings list.
    """
    if not is_enabled() or not findings:
        return
    pair = _get_or_create_for_repo(repo_url)
    if not pair:
        return
    _, thread_id = pair

    body = "\n".join(
        f"- [{f.get('severity', '?')}] {f.get('rule_id', '?')} at "
        f"{f.get('file', '?')}:{f.get('line', '?')} — "
        f"exploitable={f.get('exploitable', False)}, "
        f"fix: {f.get('fix', '?')}"
        for f in findings
    )
    content = f"New scan completed. Findings:\n{body}"

    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(
                f"{_BASE}/threads/{thread_id}/messages",
                headers=_headers(),
                json={"content": content, "stream": False, "memory": "Auto"},
            )
            r.raise_for_status()
            log.info("Backboard appended %d findings for %s", len(findings), repo_url)
    except (httpx.HTTPError, KeyError, ValueError) as e:
        log.warning("Backboard append failed for %s: %s", repo_url, e)
