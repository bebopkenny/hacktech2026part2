# SentinelAI — Technical Build Spec

## What This Is
A security analysis tool. User pastes a GitHub repo URL, backend clones it, runs Semgrep (static analysis), then sends each finding + surrounding code context to a reasoning model (K2-Think-v2) that determines if the vulnerability is actually exploitable. Backboard provides per-repo memory so re-scans recognize recurring vs. fixed vs. new findings. Frontend shows results.

## Architecture
```
                                         ┌────────────────────────┐
                                         │ K2-Think-v2 (reasoner) │
                                         └────────────┬───────────┘
                                                      │ per-finding verdict
React (Vite) ──► FastAPI ──► Semgrep CLI ──► analyzer ┤
                                                      │ scan history
                                         ┌────────────┴───────────┐
                                         │ Backboard (memory)     │
                                         └────────────────────────┘
```

No WebSocket. No database (Backboard is the memory store). Synchronous pipeline with polling for status. Backboard is optional — if `BACKBOARD_API_KEY` is unset, the pipeline runs without cross-scan memory.

---

## Repo Structure

```
sentinelai/
├── backend/
│   ├── main.py              # FastAPI app, all routes, pipeline orchestrator
│   ├── scanner.py           # git clone + semgrep subprocess (5 rulesets)
│   ├── context.py           # collect relevant files per finding
│   ├── analyzer.py          # K2-Think-v2 prompt + parse response
│   ├── backboard_client.py  # per-repo persistent memory layer
│   ├── models.py            # pydantic schemas
│   ├── requirements.txt     # fastapi, uvicorn, httpx, openai, semgrep, dotenv
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api.js           # fetch wrappers
│   │   └── components/
│   │       ├── ScanForm.jsx
│   │       ├── StatusBar.jsx
│   │       ├── FindingCard.jsx
│   │       ├── FindingList.jsx
│   │       └── Dashboard.jsx
│   ├── package.json
│   └── vite.config.js
├── docker-compose.yml
└── README.md
```

---

## Backend (Python FastAPI)

### main.py — Routes

Three endpoints + one in-memory store:

```python
scans = {}  # scan_id -> {status, progress, raw_count, confirmed_count, findings}
```

**POST /scan**
- Accepts: `{url: string, pat?: string}`
- Generates a `scan_id` (uuid4)
- Stores `scans[scan_id] = {status: "cloning", ...}`
- Kicks off pipeline in a background thread (use `threading.Thread` — no celery, no asyncio complexity)
- Returns: `{scan_id}`

**GET /scan/{scan_id}/status**
- Returns: `{status: "cloning" | "scanning" | "analyzing" | "complete" | "error", progress?: "3/7 findings"}`
- Frontend polls this every 2 seconds

**GET /findings/{scan_id}**
- Returns: `{raw_count, confirmed_count, findings: [...]}`
- Only meaningful once status = "complete"

Add CORS middleware for frontend dev (`allow_origins=["*"]`).

### scanner.py — Clone + Semgrep

Two functions:

`clone_repo(url, pat=None) -> str`
- git clone --depth 1 into a tempdir
- If PAT provided, inject into URL: `https://{pat}@github.com/...`
- Returns path to cloned repo

`run_semgrep(repo_path) -> list[dict]`
- Runs: `semgrep --config p/owasp-top-ten --config p/secrets --json {repo_path}`
- Via subprocess.run with capture_output=True
- Parses stdout as JSON
- Returns `results` array — each item has: rule id, file path, line number, matched code, severity

### context.py — File Collection

`assemble_context(repo_path, finding) -> dict`
- Reads the flagged file (full contents)
- Parses import/require statements to find related files
- Looks for common patterns: routes/, middleware/, auth/, db/, models/
- Caps at 10 files total per finding
- Returns: `{finding: {...}, files: {filepath: contents, ...}}`

Keep this simple. For JS: regex for `require()` and `import`. For Python: regex for `import` and `from ... import`. Don't build an AST parser — good enough beats perfect at 3 AM.

### analyzer.py — Reasoning Model (K2-Think-v2)

`analyze_finding(context_bundle, prior_context: str = "") -> dict`
- Builds a prompt with:
  - The Semgrep finding details (rule, file, line, matched code)
  - All collected file contents
  - `prior_context` block (from Backboard, see below) — empty string when memory is disabled or it's the first scan of this repo
  - Output schema instructions, ending with `### ANSWER` marker
- Calls K2-Think-v2 via `api.k2think.ai`'s OpenAI-compatible endpoint (`openai` SDK with `base_url`).
- Strips `<think>...</think>` blocks K2 emits before its answer, then parses the JSON object after `### ANSWER`.
- One automatic retry with a stricter prompt nudge on transient API errors or unparseable output.

**Prompt must request this JSON output:**
```json
{
  "exploitable": true/false,
  "confidence": "high" | "medium" | "low",
  "taint_path": "req.query.username (routes/auth.js:34) → db.findOne (db/users.js:41)",
  "auth_gap": "auth check on line 38 runs after the query",
  "exploit_steps": ["step 1", "step 2", "step 3"],
  "severity": "critical" | "high" | "medium" | "low",
  "fix": "use parameterized query or validate input type"
}
```

**Prompt constraints:**
- Model must cite specific file and line numbers for every claim
- Model must not invent vulnerabilities Semgrep didn't flag
- Model must assess: does sanitization/validation already cover this? Is the input actually user-controlled? Does auth middleware protect this route?
- If the finding is not exploitable, set exploitable=false and explain why

### backboard_client.py — Per-Repo Memory

Backboard is a hosted thread + memory API ([docs.backboard.io](https://docs.backboard.io)). We use it as a persistent store for "what we've seen on this repo before," so a re-scan after a code change can flag recurring/fixed/new findings instead of treating each scan as cold.

**Architecture decision:** one Backboard *assistant* + one *thread* per GitHub repo URL. Memory in Backboard is assistant-scoped (facts persist across all threads under the same assistant), so a shared assistant would leak repo A's facts into repo B's analysis. Per-repo isolation keeps memory clean.

**Mapping persistence:** `{repo_url: (assistant_id, thread_id)}` is JSON-serialized to `/tmp/sentinelai/backboard_repos.json` (lock-protected with `threading.Lock`). Survives container restarts because `/tmp/sentinelai/` is volume-mounted.

**Three entry points:**
- `is_enabled() -> bool` — `True` iff `BACKBOARD_API_KEY` is set. Callers short-circuit when `False`.
- `get_history_summary(repo_url) -> str` — POSTs a "summarize prior findings" message to the repo's thread with `memory: "Readonly"`. Returns the assistant's reply, or `""` on failure / first scan.
- `append_findings(repo_url, findings) -> None` — POSTs the scan's confirmed findings as one message with `memory: "Auto"`, so Backboard's auto-extraction stores facts for next time.

**Failure mode:** every Backboard call is wrapped in try/except. Outages, rate limits, or malformed responses log a warning and return `""` / `None`. The K2 path keeps working — scans never fail because of Backboard.

### models.py — Pydantic Schemas

```python
class ScanRequest(BaseModel):
    url: str
    pat: str | None = None

class Finding(BaseModel):
    rule_id: str
    file: str
    line: int
    matched_code: str
    exploitable: bool
    confidence: str
    taint_path: str | None
    auth_gap: str | None
    exploit_steps: list[str]
    severity: str
    fix: str

class ScanResult(BaseModel):
    scan_id: str
    status: str
    progress: str | None
    raw_count: int
    confirmed_count: int
    findings: list[Finding]
```

### Pipeline Flow (runs in background thread)

```
1. clone_repo(url, pat) → repo_path
   update status: "scanning"

2. run_semgrep(repo_path) → raw_findings
   update status: "analyzing", raw_count = len(raw_findings)

3. prior_context = backboard_client.get_history_summary(url)
   # "" if Backboard disabled or first scan of this repo

4. for i, finding in enumerate(raw_findings):
     context = assemble_context(repo_path, finding)
     result = analyze_finding(context, prior_context=prior_context)
     if result["exploitable"]:
       append to confirmed findings
     update progress: f"{i+1}/{len(raw_findings)} findings"

5. update status: "complete", set confirmed_count and findings

6. backboard_client.append_findings(url, confirmed)
   # writes this scan's verdicts to the repo's thread for next time

7. cleanup: shutil.rmtree(repo_path)
```

The Backboard calls in steps 3 and 6 are no-ops when `BACKBOARD_API_KEY` is unset. They never raise — failures degrade silently to "no memory available."

### Dockerfile

```dockerfile
FROM python:3.11-slim
RUN pip install semgrep
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### requirements.txt
```
fastapi
uvicorn
httpx
pydantic
```

---

## Frontend (React + Vite)

### Setup
```bash
npm create vite@latest frontend -- --template react
cd frontend && npm install
```

Use Tailwind CSS for styling. The UI should feel like a security tool — dark theme, monospace for code, severity colors (red/orange/yellow/green).

### Components

**App.jsx**
- Top-level layout. Header with "SentinelAI" branding. Holds scan state.
- States: `idle` → `scanning` → `results`

**ScanForm.jsx**
- Text input for GitHub URL
- Optional text input for PAT (type=password)
- "Scan" button
- On submit: POST to /scan, get scan_id, switch to scanning state

**StatusBar.jsx**
- Receives scan_id as prop
- Polls GET /scan/{scan_id}/status every 2 seconds
- Displays: "Cloning repository..." → "Running Semgrep..." → "Analyzing finding 3/7..." → done
- When status = "complete", triggers parent to fetch findings

**Dashboard.jsx**
- Shows the key contrast: "Semgrep found {raw_count} candidates → {confirmed_count} confirmed exploitable"
- This is the #1 demo moment. Make these numbers big and visually prominent.
- Severity breakdown: count of critical/high/medium/low

**FindingList.jsx**
- Maps over findings array
- Renders FindingCard for each
- Sorted by severity (critical first)

**FindingCard.jsx**
- Collapsed: severity badge + rule_id + file:line + exploitable verdict
- Expanded (click to toggle):
  - Taint path (monospace, with file:line references)
  - Auth gap assessment
  - Exploit steps (numbered list)
  - Fix recommendation
  - Confidence indicator
- Color-code severity: critical=red, high=orange, medium=yellow, low=green

### api.js
```javascript
const API = "http://localhost:8000";  // change for prod

export async function startScan(url, pat) {
  const res = await fetch(`${API}/scan`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url, pat: pat || null})
  });
  return res.json(); // {scan_id}
}

export async function getStatus(scanId) {
  const res = await fetch(`${API}/scan/${scanId}/status`);
  return res.json(); // {status, progress}
}

export async function getFindings(scanId) {
  const res = await fetch(`${API}/findings/${scanId}`);
  return res.json(); // {raw_count, confirmed_count, findings}
}
```

---

## Deploy to Vultr

Vultr box is already provisioned. Deploy steps:
1. SSH in, clone the repo
2. `docker-compose up -d` for backend
3. Frontend: either serve built files from nginx on the same box, or deploy to Vercel
4. Set env vars: K2_API_KEY (and optionally K2_BASE_URL, K2_MODEL, DOMAIN)
5. Open port 8000 (backend) in firewall

docker-compose.yml:
```yaml
version: "3.8"
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - K2_API_KEY=${K2_API_KEY}
    volumes:
      - /tmp/sentinelai:/tmp/sentinelai
```

---

## Demo Repos for Testing
- vulnerable-node (GitHub) — Node.js with SQL injection, XSS, insecure auth
- Any DVWA-equivalent Flask/Django app for Python coverage
- These should produce 15-25 raw Semgrep findings → 3-7 confirmed exploitable

---

## What NOT to Build
- No database / Postgres — in-memory dict is fine
- No WebSocket — polling with /status endpoint
- No OAuth — PAT field only
- No file upload — URL input only
- No languages beyond JS and Python
- No user accounts or auth on the app itself
- No tests — test by running the demo