"""
Handles repo cloning and Semgrep execution.

clone_repo(url, pat=None) -> str
  - git clone --depth 1 into a tempdir
  - injects PAT into URL for private repos: https://{pat}@github.com/...
  - returns path to cloned repo

run_semgrep(repo_path) -> list[dict]
  - runs semgrep with 5 curated security rulesets, writes JSON to a temp file
  - returns results[] — each entry has: check_id, path, start.line,
    extra.lines, extra.severity, extra.message
  - requires SEMGREP_APP_TOKEN env var in Docker/Vultr (set via semgrep login locally)
"""
import json
import os
import subprocess
import tempfile


class CloneError(RuntimeError):
    """Raised when cloning fails, with a user-readable message."""


def _friendly_clone_error(stderr: str) -> str:
    """Map git stderr to a short message we can show in the UI."""
    s = (stderr or "").lower()
    if "repository not found" in s or "not found" in s and "github.com" in s:
        return "Repository not found. Check the URL, and if it's private, supply a PAT with repo access."
    if "could not resolve host" in s or "could not read from remote" in s:
        return "Couldn't reach GitHub from the server. Network or DNS issue."
    if "authentication failed" in s or "invalid username or password" in s or "http 401" in s:
        return "Authentication failed. The PAT is missing, expired, or lacks repo scope."
    if "permission denied" in s or "http 403" in s:
        return "Permission denied. The PAT doesn't have access to this repository."
    if "fatal:" in s:
        # Pull the first 'fatal: ...' line out for a concise message.
        for line in (stderr or "").splitlines():
            line = line.strip()
            if line.lower().startswith("fatal:"):
                return line[6:].strip().rstrip(".") or "git clone failed."
    return "git clone failed. The repository may be invalid or unreachable."


def clone_repo(url: str, pat: str | None = None) -> str:
    if pat and "github.com" in url:
        url = url.replace("https://", f"https://{pat}@")

    os.makedirs("/tmp/sentinelai", exist_ok=True)
    dest = tempfile.mkdtemp(prefix="sentinelai_", dir="/tmp/sentinelai")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        # Strip the dest tempdir if the clone left it behind.
        try:
            if os.path.isdir(dest):
                import shutil as _sh
                _sh.rmtree(dest, ignore_errors=True)
        except Exception:
            pass
        raise CloneError(_friendly_clone_error(e.stderr)) from e
    return dest


def run_semgrep(repo_path: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    cmd = [
        "semgrep",
        "--config", "p/owasp-top-ten",
        "--config", "p/secrets",
        "--config", "p/sql-injection",
        "--config", "p/nodejs",
        "--config", "p/python",
        "--max-target-bytes", "5000000",
        "--timeout", "60",
        "--metrics", "off",  # skip telemetry HTTP call (~100-500ms saved per scan)
        "--json",
        "--output", output_path,
        repo_path,
    ]
    # Optional explicit job count for constrained Docker hosts where semgrep's
    # auto-detect (= os.cpu_count()) may not reflect the cgroup CPU quota. Left
    # unset by default so semgrep uses its own default (all detected cores).
    jobs = os.getenv("SEMGREP_JOBS")
    if jobs:
        cmd.extend(["--jobs", jobs])

    try:
        subprocess.run(cmd, capture_output=True, text=True)
        with open(output_path, "r") as f:
            data = json.load(f)
        return data.get("results", [])
    except (json.JSONDecodeError, OSError):
        return []
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
