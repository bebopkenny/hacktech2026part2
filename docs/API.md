# SentinelAI Backend API

Base URL: `http://<vultr-ip>:8000` in prod, `http://localhost:8000` in dev.
CORS is wide open, so the frontend can call directly from any origin.

All requests/responses are JSON. There is **no authentication** on the API
(demo scope).

**Per-repo memory (Backboard):** when the backend has `BACKBOARD_API_KEY`
configured, findings persist across scans of the same repo via Backboard's
thread + memory API. The first scan of a repo is just analysis; subsequent
scans of the same `url` get prior-finding context injected into the reasoning
prompt, so the model can flag recurring vs. fixed vs. new issues.

No frontend changes needed — the API surface is identical, the `findings`
array's prose fields (`taint_path`, `auth_gap`, `exploit_steps`, `fix`) just
become richer on re-scans (e.g. *"This SQLi at users.js:41 was flagged in the
previous scan and remains unfixed"*).

If `BACKBOARD_API_KEY` is unset or Backboard is unreachable, scans still run —
just without memory. The frontend doesn't need to detect this state.

---

## Lifecycle

```
POST /scan ──► {scan_id}
                  │
                  ▼
   poll every 2s: GET /scan/{scan_id}/status
                  │
       status == "complete" or "error"
                  │
                  ▼
        GET /findings/{scan_id}
```

Status values, in order: `cloning` → `scanning` → `analyzing` → `complete`.
Any failure sets status to `error` and populates the `error` field.

---

## Endpoints

### `GET /health`

Liveness probe. Returns `{"ok": true}`. Use it to check the backend is up.

### `POST /scan`

Kick off a scan. Returns immediately; the pipeline runs in the background.

**Request body**
```json
{
  "url": "https://github.com/owner/repo",
  "pat": "ghp_..."
}
```
- `url` (required) — public or private GitHub repo URL.
- `pat` (optional) — GitHub Personal Access Token, only needed for private repos. The frontend should expose this as a `type=password` field.

**Response — 200**
```json
{ "scan_id": "a1b2c3..." }
```

**Errors**
- `422` — invalid body (missing `url`).

### `GET /scan/{scan_id}/status`

Poll this every 2 seconds until `status` is `complete` or `error`.

**Response — 200**
```json
{
  "status": "analyzing",
  "progress": "3/7 findings",
  "error": null
}
```
- `status` ∈ `cloning | scanning | analyzing | complete | error`.
- `progress` is `null` until the analyzing phase, then `"{i}/{total} findings"`.
- `error` is `null` unless `status == "error"`.

**Errors**
- `404` — unknown `scan_id`.

### `GET /findings/{scan_id}`

Fetch results. Safe to call at any point — `findings` accumulates as the
pipeline confirms exploitable vulns, so a UI that wants to stream results can
poll this instead of `/status`. Most clients should just call it once after
status hits `complete`.

**Response — 200**
```json
{
  "scan_id": "a1b2c3...",
  "status": "complete",
  "raw_count": 24,
  "confirmed_count": 5,
  "findings": [
    {
      "rule_id": "javascript.express.security.audit.express-mongo-sanitize.express-mongo-sanitize",
      "file": "routes/auth.js",
      "line": 34,
      "matched_code": "db.users.findOne({ username: req.query.username })",
      "exploitable": true,
      "confidence": "high",
      "taint_path": "req.query.username (routes/auth.js:34) → db.findOne (db/users.js:41)",
      "auth_gap": "auth middleware on line 38 runs after the query",
      "exploit_steps": [
        "Send GET /login?username[$ne]=null",
        "Mongo returns the first user document",
        "Server issues a session for that user"
      ],
      "severity": "critical",
      "fix": "Validate req.query.username is a string before querying."
    }
  ]
}
```

`raw_count` is total Semgrep findings; `confirmed_count` is the subset the AI
deemed exploitable. The headline UI moment is `raw_count → confirmed_count`.

**Errors**
- `404` — unknown `scan_id`.

---

## Reference frontend client

Drop-in replacement for `frontend/src/api.js`:

```javascript
const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export async function startScan(url, pat) {
  const res = await fetch(`${API}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, pat: pat || null }),
  });
  if (!res.ok) throw new Error(`scan failed: ${res.status}`);
  return res.json(); // { scan_id }
}

export async function getStatus(scanId) {
  const res = await fetch(`${API}/scan/${scanId}/status`);
  if (!res.ok) throw new Error(`status failed: ${res.status}`);
  return res.json(); // { status, progress, error }
}

export async function getFindings(scanId) {
  const res = await fetch(`${API}/findings/${scanId}`);
  if (!res.ok) throw new Error(`findings failed: ${res.status}`);
  return res.json(); // { scan_id, status, raw_count, confirmed_count, findings[] }
}

// Convenience: poll until terminal, with a 2s interval.
export async function pollUntilDone(scanId, onTick) {
  while (true) {
    const s = await getStatus(scanId);
    onTick?.(s);
    if (s.status === "complete" || s.status === "error") return s;
    await new Promise(r => setTimeout(r, 2000));
  }
}
```

Use `VITE_API_URL` so dev points at `http://localhost:8000` and the deployed
frontend points at the Vultr box. Set it in `frontend/.env.production`.

---

## TypeScript types

```ts
export type Status = "cloning" | "scanning" | "analyzing" | "complete" | "error";

export interface ScanStatus {
  status: Status;
  progress: string | null;        // "3/7 findings" once analyzing
  error: string | null;
}

export interface Finding {
  rule_id: string;
  file: string;
  line: number;
  matched_code: string;
  exploitable: boolean;
  confidence: "high" | "medium" | "low";
  taint_path: string | null;
  auth_gap: string | null;
  exploit_steps: string[];
  severity: "critical" | "high" | "medium" | "low";
  fix: string;
}

export interface ScanResult {
  scan_id: string;
  status: Status;
  raw_count: number;
  confirmed_count: number;
  findings: Finding[];
}
```
