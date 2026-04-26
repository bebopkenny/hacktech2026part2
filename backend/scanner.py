"""
Handles repo cloning and Semgrep execution.

clone_repo(url, pat=None) -> str
  - git clone --depth 1 into a tempdir
  - injects PAT into URL for private repos: https://{pat}@github.com/...
  - returns path to cloned repo

run_semgrep(repo_path) -> list[dict]
  - runs: semgrep --config p/owasp-top-ten --config p/secrets --json {repo_path}
  - parses stdout JSON, returns results[]
  - each result has: check_id, path, start.line, extra.lines, extra.severity, extra.message
"""
import json
import os
import subprocess
import tempfile


def clone_repo(url: str, pat: str | None = None) -> str:
    if pat and "github.com" in url:
        url = url.replace("https://", f"https://{pat}@")

    os.makedirs("/tmp/sentinelai", exist_ok=True)
    dest = tempfile.mkdtemp(prefix="sentinelai_", dir="/tmp/sentinelai")
    subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def run_semgrep(repo_path: str) -> list[dict]:
    result = subprocess.run(
        [
            "semgrep",
            "--config", "p/owasp-top-ten",
            "--config", "p/secrets",
            "--json",
            repo_path,
        ],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(result.stdout)
        return data.get("results", [])
    except json.JSONDecodeError:
        return []
