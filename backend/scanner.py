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
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    try:
        subprocess.run(
            [
                "semgrep",
                "--config", "p/owasp-top-ten",
                "--config", "p/secrets",
                "--config", "p/sql-injection",
                "--config", "p/nodejs",
                "--config", "p/python",
                "--max-target-bytes", "5000000",
                "--timeout", "60",
                "--json",
                "--output", output_path,
                repo_path,
            ],
            capture_output=True,
            text=True,
        )
        with open(output_path, "r") as f:
            data = json.load(f)
        return data.get("results", [])
    except (json.JSONDecodeError, OSError):
        return []
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
