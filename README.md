# SentinelAI

**Connect your repo. See why it's exploitable.**

> Hacktech 2026 · California Institute of Technology · April 24–26

Static analysis tools have a precision problem. Semgrep fires hundreds of findings and developers ignore all of them. The hard part isn't detection — it's knowing which findings are actually exploitable in your specific codebase. That requires reading your code the way a senior security engineer would. SentinelAI does that in seconds.

---

## What it does

SentinelAI is a two-layer security analysis pipeline:

**Layer 1 — Semgrep (deterministic detection)**
Runs `p/owasp-top-ten`, `p/secrets`, `p/sql-injection`, `p/nodejs`, and `p/python` against the cloned repo. Produces structured JSON candidates. Fast, zero hallucinations. If Semgrep doesn't flag it, SentinelAI doesn't flag it.

**Layer 2 — K2-Think-v2 (reasoning)**
For each Semgrep finding, the reasoning model receives the flagged file plus all relevant context — the route file, auth middleware, database layer — and performs four tasks:

| Task | What the model actually does |
|---|---|
| Exploitability verdict | Reads full context and decides: is this real, or does existing sanitization cover it? |
| Cross-file taint tracing | Follows the data from the input source across files to the sensitive sink |
| Auth coverage check | Reads the middleware chain to determine whether auth actually protects this route |
| Exploit narrative | Constructs a step-by-step attacker path grounded in your actual code |

Non-exploitable findings are suppressed. Only confirmed vulnerabilities reach the dashboard. The contrast — *23 Semgrep candidates → 4 confirmed exploitable* — is the product.

---

## Live deployment

| | URL |
|---|---|
| **Frontend** | Deployed on Vercel |
| **Backend** | `http://107.191.50.160:8000` (Vultr) |
| **Domain** | `.tech` domain — coming soon |

---

## Architecture

```
React (Vercel)
     │  POST /scan
     │  WS /ws  ──── live finding_ready events
     ▼
FastAPI (Vultr)
     │
     ├── git clone (public URL or PAT-injected for private repos)
     │
     ├── Semgrep CLI (5 rulesets) → raw findings JSON
     │
     ├── context.py → flagged file + imports + auth/db/middleware (cap 10 files)
     │
     ├── K2-Think-v2 × N findings (parallel, K2_PARALLEL workers)
     │        └── exploitable? taint_path, auth_gap, exploit_steps, fix
     │
     ├── Backboard (optional) → per-repo persistent memory across scans
     │
     └── POST /webhook/github → auto-rescan on every git push (HMAC-verified)
```

No database. In-memory scan store is sufficient for demo. Backboard provides cross-scan memory if `BACKBOARD_API_KEY` is set.

---

## Per-finding output

```json
{
  "rule_id": "javascript.express.nosql-injection",
  "file": "routes/auth.js",
  "line": 34,
  "matched_code": "db.findOne({ username: req.query.username })",
  "exploitable": true,
  "confidence": "high",
  "taint_path": "req.query.username (routes/auth.js:34) → passed unsanitized to db.findOne() (db/users.js:41)",
  "auth_gap": "Auth check on line 38 runs after the query — injection fires before authentication.",
  "exploit_steps": [
    "Send GET /login?username={\"$gt\":\"\"}",
    "MongoDB matches first document in users collection",
    "Credential check bypassed entirely — full admin access"
  ],
  "severity": "critical",
  "fix": "Validate input is a plain string before querying."
}
```

Every output contains: exploitable verdict, taint path with file/line evidence, auth gap assessment, step-by-step exploit, and a concrete fix. All claims are grounded in specific lines of your actual code.

---

## Running locally

### Prerequisites
- Docker + docker-compose
- Node.js 18+
- A K2-Think-v2 API key from [api.k2think.ai](https://api.k2think.ai)
- A Semgrep token (`semgrep login` → `cat ~/.semgrep/settings.yml`)

### Backend

```bash
git clone https://github.com/your-org/sentinelai
cd sentinelai
cp .env.example .env
# Fill in K2_API_KEY and SEMGREP_APP_TOKEN at minimum
docker-compose up --build
# Backend running at http://localhost:8000
```

### Frontend

```bash
cd frontend
echo "VITE_API_URL=http://localhost:8000" > .env
npm install
npm run dev
# Frontend at http://localhost:5173
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `K2_API_KEY` | Yes | K2-Think-v2 API key — [api.k2think.ai](https://api.k2think.ai) |
| `K2_BASE_URL` | No | Defaults to `https://api.k2think.ai/v1` |
| `K2_MODEL` | No | Defaults to `MBZUAI-IFM/K2-Think-v2` |
| `K2_PARALLEL` | No | Concurrent K2 calls per scan. Default `5`. Raise for speed, lower to debug. |
| `SEMGREP_APP_TOKEN` | Yes | Required for `p/` registry rulesets in Docker. |
| `BACKBOARD_API_KEY` | No | Enables per-repo persistent memory. Without it, every scan runs cold. |
| `BACKBOARD_MODEL` | No | Model for Backboard memory summarization. Default `gpt-4o-mini`. |
| `GITHUB_WEBHOOK_SECRET` | No | Required to receive push webhooks. Generate: `openssl rand -hex 32`. |

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/scan` | Start a scan. Body: `{"url": "...", "pat": "..."}`. Returns `{scan_id}`. |
| `GET` | `/scan/{scan_id}/status` | Poll: `cloning` → `scanning` → `analyzing` → `complete` \| `error` |
| `GET` | `/findings/{scan_id}` | Full results. Returns `{raw_count, confirmed_count, findings}` |
| `WS` | `/ws` | Live stream: `scan_started`, `semgrep_done`, `finding_ready`, `scan_complete` |
| `POST` | `/webhook/github` | GitHub push event receiver (HMAC-SHA256 verified) |
| `GET` | `/health` | Liveness probe |

---

## GitHub webhook setup

1. Set `GITHUB_WEBHOOK_SECRET` in `.env`: `openssl rand -hex 32`
2. In your target repo: **Settings → Webhooks → Add webhook**
   - Payload URL: `https://your-backend-url/webhook/github`
   - Content type: `application/json`
   - Secret: same value as `GITHUB_WEBHOOK_SECRET`
   - Events: push only
3. Every `git push` now triggers a full rescan. Results stream live to the dashboard.

---

## Demo repos

Reliable targets that produce 10–25 Semgrep candidates with several confirmed exploitable:

- [vulnerable-node](https://github.com/cr0hn/vulnerable-node) — Node.js, SQL injection + XSS + insecure auth
- [DVWA](https://github.com/digininja/DVWA) — broad vulnerability coverage across multiple classes
- Any Flask/FastAPI app with raw string interpolation into SQL queries

---

## Scope

**In scope (MVP):** Public + private GitHub repos, JavaScript (Express/Node) and Python (Flask/FastAPI/Django), false positive filtering, real-time WebSocket results, GitHub push webhooks.

**Explicitly out of scope:** GitHub OAuth, dependency scanning, languages beyond JS/Python, VS Code extension, CI/CD integration, team dashboards.
