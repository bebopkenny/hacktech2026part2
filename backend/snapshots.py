"""
Per-repo finding snapshot storage — drives severity-escalation detection.

The PRD's "MEDIUM → CRITICAL" demo moment fires when a finding's severity
rises between scans (e.g. a new file landed that connects a previously-
flagged input to a sink). We surface this with an `escalated_from` value
on the finding so the frontend can render the badge in FindingCard.jsx.

Storage: one JSON file per repo at /tmp/sentinelai/snapshots/<slug>.json,
mapping {finding_key: severity_string}. The host /tmp/sentinelai/ is
volume-mounted into the Docker container, so snapshots survive restarts.

This is a separate layer from Backboard. Backboard stores findings as
prose for K2 to reason about; snapshots store structured severity data
for fast diffing. Different jobs, different shapes.

Failure mode: I/O errors return an empty snapshot / silent no-op write.
Escalation is a bonus feature — it must never break the scan.
"""
import json
import logging
import os
import re
import threading
from pathlib import Path

log = logging.getLogger("snapshots")

_SNAPSHOT_DIR = Path(os.getenv("SNAPSHOT_DIR", "/tmp/sentinelai/snapshots"))
_lock = threading.Lock()

# Lower index = lower severity. Used to detect rises only.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _slug(repo_url: str) -> str:
    """Stable filesystem-safe filename for a repo URL."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", repo_url)[:200]


def _path(repo_url: str) -> Path:
    return _SNAPSHOT_DIR / f"{_slug(repo_url)}.json"


def _key(finding: dict) -> str:
    """Stable identity for a finding across scans."""
    return f"{finding.get('rule_id', '?')}|{finding.get('file', '?')}|{finding.get('line', 0)}"


def load(repo_url: str) -> dict[str, str]:
    """Return {key: severity} from the prior snapshot, or {} on first scan / error."""
    p = _path(repo_url)
    with _lock:
        try:
            return json.loads(p.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}


def save(repo_url: str, findings: list[dict]) -> None:
    """Persist {key: severity} for the given findings. Atomic write via tmp+rename."""
    snapshot = {_key(f): f.get("severity", "low") for f in findings}
    p = _path(repo_url)
    with _lock:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(snapshot))
            tmp.replace(p)
        except OSError as e:
            log.warning("failed to save snapshot for %s: %s", repo_url, e)


def escalation(prior: dict[str, str], finding: dict) -> str | None:
    """If `finding` is more severe than its previous version, return the
    prior severity in uppercase (matching the FindingCard badge format).
    Returns None when there's no prior entry, no change, or severity dropped.
    """
    prev = prior.get(_key(finding))
    if not prev:
        return None
    prev_rank = _SEVERITY_RANK.get(prev, -1)
    cur_rank = _SEVERITY_RANK.get(finding.get("severity", "low"), -1)
    if cur_rank > prev_rank:
        return prev.upper()
    return None
