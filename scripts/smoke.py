#!/usr/bin/env python3
"""
End-to-end smoke test for SentinelAI.

Two modes:

  python scripts/smoke.py k2
      Hits K2-Think-v2 directly with a tiny security prompt. Confirms the
      API key + base URL + model name all work. Doesn't need the backend.

  python scripts/smoke.py api [BASE_URL] [REPO_URL]
      Hits the running FastAPI backend. Defaults:
        BASE_URL = http://localhost:8000
        REPO_URL = https://github.com/OWASP/NodeGoat
      Walks: /health → POST /scan → poll /scan/{id}/status → GET /findings/{id}.

Usage examples:
  make serve-backend          # in another terminal
  python scripts/smoke.py k2
  python scripts/smoke.py api
  python scripts/smoke.py api http://<vultr-ip>:8000
  python scripts/smoke.py api http://localhost:8000 https://github.com/some/tiny-repo
"""
import os
import pathlib
import sys
import time

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Best-effort .env loader — no python-dotenv dependency.
def _load_env() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def test_k2() -> int:
    _load_env()
    api_key = os.environ.get("K2_API_KEY")
    if not api_key or api_key == "your-k2-key-here":
        print("FAIL: K2_API_KEY not set in .env (or still placeholder).")
        return 1

    base_url = os.environ.get("K2_BASE_URL", "https://api.k2think.ai/v1")
    model = os.environ.get("K2_MODEL", "MBZUAI-IFM/K2-Think-v2")

    print(f"→ K2 endpoint: {base_url}")
    print(f"→ K2 model:    {model}")
    print("→ sending tiny prompt...")

    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url=base_url)
    try:
        resp = client.chat.completions.create(
            model=model,
            max_tokens=256,
            temperature=0.3,
            stream=False,
            messages=[{
                "role": "user",
                "content": (
                    'Respond with ONLY this JSON, nothing else: '
                    '{"ok": true, "model": "k2-think-v2"}'
                ),
            }],
        )
    except Exception as e:
        print(f"FAIL: K2 call raised: {e}")
        return 1

    raw = (resp.choices[0].message.content or "").strip()
    print(f"← raw response ({len(raw)} chars):")
    print(raw[:500])
    print()
    if raw:
        print("PASS: K2 reachable, key valid, model returned content.")
        return 0
    print("FAIL: empty response.")
    return 1


def test_api(base_url: str, repo_url: str) -> int:
    print(f"→ backend: {base_url}")
    print(f"→ target:  {repo_url}")
    print()

    with httpx.Client(timeout=30.0) as c:
        # 1. health
        print("1. GET /health")
        r = c.get(f"{base_url}/health")
        print(f"   {r.status_code} {r.json()}")
        r.raise_for_status()

        # 2. start scan
        print("2. POST /scan")
        r = c.post(f"{base_url}/scan", json={"url": repo_url})
        r.raise_for_status()
        scan_id = r.json()["scan_id"]
        print(f"   scan_id = {scan_id}")

        # 3. poll status
        print("3. GET /scan/{id}/status (polling every 2s)")
        last_status = None
        deadline = time.time() + 600  # 10 min ceiling
        while time.time() < deadline:
            r = c.get(f"{base_url}/scan/{scan_id}/status")
            r.raise_for_status()
            s = r.json()
            sig = (s["status"], s.get("progress"))
            if sig != last_status:
                print(f"   {sig[0]:<10} progress={sig[1]}")
                last_status = sig
            if s["status"] in ("complete", "error"):
                if s["status"] == "error":
                    print(f"   FAIL: pipeline errored: {s.get('error')}")
                    return 1
                break
            time.sleep(2)
        else:
            print("   FAIL: timed out waiting for completion")
            return 1

        # 4. findings
        print("4. GET /findings/{id}")
        r = c.get(f"{base_url}/findings/{scan_id}")
        r.raise_for_status()
        f = r.json()
        print(f"   raw_count       = {f['raw_count']}")
        print(f"   confirmed_count = {f['confirmed_count']}")
        if f["findings"]:
            top = f["findings"][0]
            print(f"   first finding   = {top['rule_id']} @ {top['file']}:{top['line']} ({top['severity']})")
            print(f"     fix: {top['fix'][:120]}")
        print()
        print("PASS: full pipeline ran end-to-end.")
        return 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    mode = args[0]
    if mode == "k2":
        return test_k2()
    if mode == "api":
        base_url = args[1] if len(args) > 1 else "http://localhost:8000"
        repo_url = args[2] if len(args) > 2 else "https://github.com/OWASP/NodeGoat"
        return test_api(base_url.rstrip("/"), repo_url)

    print(f"unknown mode: {mode}")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
