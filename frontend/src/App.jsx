import React, { useState, useCallback, useRef, useEffect } from "react";
import Header from "./Header.jsx";
import ScanForm from "./ScanForm.jsx";
import ScanProgress from "./ScanProgress.jsx";
import FindingCard from "./FindingCard.jsx";
import RiskScore from "./RiskScore.jsx";
import EmptyState from "./EmptyState.jsx";
import { useWebSocket } from "./useWebSocket.js";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_URL = API.replace(/^http/, "ws") + "/ws";

// Shareable URLs: ?scan=<id> rehydrates a session from the backend on load.
function readScanIdFromUrl() {
  if (typeof window === "undefined") return null;
  return new URLSearchParams(window.location.search).get("scan");
}
function writeScanIdToUrl(scanId) {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  if (scanId) url.searchParams.set("scan", scanId);
  else url.searchParams.delete("scan");
  window.history.replaceState(null, "", url.toString());
}

// ── mock data so the UI looks alive without a backend ──────────────────────
const MOCK_FINDINGS = [
  {
    id: 1,
    rule_id: "javascript.express.nosql-injection",
    severity: "CRITICAL",
    file: "routes/auth.js",
    line: 34,
    matched_code: 'db.findOne({ username: req.query.username })',
    exploitable: true,
    taint_path: "req.query.username (routes/auth.js:34) → passed unsanitized to db.findOne() (db/users.js:41)",
    auth_gap: "Auth check on line 38 runs AFTER the query — injection fires before authentication.",
    exploit_steps: [
      'Send GET /login?username={"$gt":""}',
      "MongoDB matches first document in users collection",
      "Credential check bypassed entirely — full admin access",
    ],
    fix: 'Validate input is a plain string before querying: if (typeof req.query.username !== "string") return res.status(400).json({error:"Invalid input"})',
    confidence: "high",
    escalated_from: null,
  },
  {
    id: 2,
    rule_id: "javascript.express.xss-reflected",
    severity: "HIGH",
    file: "routes/search.js",
    line: 19,
    matched_code: 'res.send("<h1>Results for: " + req.query.q + "</h1>")',
    exploitable: true,
    taint_path: "req.query.q (routes/search.js:19) → directly concatenated into HTML response",
    auth_gap: "Route is publicly accessible, no authentication required.",
    exploit_steps: [
      "GET /search?q=<script>document.cookie</script>",
      "Response reflects raw input into page HTML",
      "Executes attacker JS in victim's browser session",
    ],
    fix: "Use a template engine with auto-escaping, or manually escape: const safe = q.replace(/</g,'&lt;').replace(/>/g,'&gt;')",
    confidence: "high",
    escalated_from: null,
  },
  {
    id: 3,
    rule_id: "python.flask.sql-injection",
    severity: "HIGH",
    file: "api/users.py",
    line: 52,
    matched_code: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    exploitable: true,
    taint_path: "user_id from request path (api/users.py:48) → f-string interpolated into raw SQL",
    auth_gap: "JWT middleware present but only validates token existence, not role. Any authenticated user can exploit.",
    exploit_steps: [
      "GET /api/users/1 OR 1=1--",
      "SQL comment drops the WHERE clause",
      "Full users table returned — all credentials exposed",
    ],
    fix: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    confidence: "high",
    escalated_from: "MEDIUM",
  },
  {
    id: 4,
    rule_id: "javascript.secrets.hardcoded-jwt-secret",
    severity: "MEDIUM",
    file: "config/auth.js",
    line: 3,
    matched_code: 'const JWT_SECRET = "supersecret123"',
    exploitable: true,
    taint_path: "Hardcoded secret used in jwt.sign() calls across 3 files",
    auth_gap: "Any attacker with repo read access can forge arbitrary JWT tokens.",
    exploit_steps: [
      "Read JWT_SECRET from source / git history",
      "Forge JWT: jwt.sign({id:1,role:'admin'}, 'supersecret123')",
      "Full admin impersonation on any endpoint",
    ],
    fix: "Move to environment variable: process.env.JWT_SECRET. Rotate the current secret immediately.",
    confidence: "high",
    escalated_from: null,
  },
  {
    id: 5,
    rule_id: "javascript.express.path-traversal",
    severity: "LOW",
    file: "routes/files.js",
    line: 27,
    matched_code: 'fs.readFile("./uploads/" + req.params.filename)',
    exploitable: false,
    taint_path: "req.params.filename → path.join with uploads dir",
    auth_gap: "Route requires authentication. Sanitization on line 22 checks for '..' sequences.",
    exploit_steps: [],
    fix: "Existing sanitization covers the flagged case. Consider path.resolve() + startsWith check as defence-in-depth.",
    confidence: "high",
    escalated_from: null,
  },
];

export default function App() {
  const [phase, setPhase] = useState("idle"); // idle | scanning | done
  const [findings, setFindings] = useState([]);
  const [progress, setProgress] = useState({ step: "", pct: 0, raw_count: 0 });
  const [repoUrl, setRepoUrl] = useState("");
  const [useMock, setUseMock] = useState(false);
  const mockTimer = useRef(null);
  // Tracks the scan_id we're currently watching. Late-arriving events from
  // earlier scans (e.g. K2 retries finishing after a new scan started) get
  // filtered out so they don't pollute the current view.
  const currentScanIdRef = useRef(null);

  // WebSocket handler
  const handleWsMessage = useCallback((data) => {
    if (data.type === "scan_started") {
      // New scan takes over the dashboard — webhook-triggered or manual.
      currentScanIdRef.current = data.scan_id || null;
      if (data.scan_id) writeScanIdToUrl(data.scan_id);
      setPhase("scanning");
      setFindings([]);
      setProgress({ step: "Cloning repository…", pct: 10, raw_count: 0 });
      if (data.url) setRepoUrl(data.url);
      return;
    }

    // Drop events that don't match the scan we're currently watching.
    if (data.scan_id && currentScanIdRef.current && data.scan_id !== currentScanIdRef.current) return;

    if (data.type === "semgrep_done") {
      setProgress({ step: `Semgrep found ${data.count} candidates — running AI analysis…`, pct: 35, raw_count: data.count });
    } else if (data.type === "finding_ready") {
      setFindings((f) => [...f, data.finding]);
      setProgress((p) => ({ ...p, step: `Analysing finding ${data.index + 1} of ${data.total}…`, pct: 35 + Math.round((data.index / data.total) * 55) }));
    } else if (data.type === "scan_complete") {
      setPhase("done");
      setProgress({ step: "Scan complete", pct: 100, raw_count: data.raw_count });
    }
  }, []);

  const { connected } = useWebSocket(WS_URL, handleWsMessage);

  // Mock scan for demo / no-backend mode
  const runMockScan = useCallback((url) => {
    setRepoUrl(url);
    setPhase("scanning");
    setFindings([]);

    const steps = [
      { step: "Cloning repository…", pct: 10, delay: 600 },
      { step: "Running Semgrep (p/owasp-top-ten, p/secrets, p/sql-injection)…", pct: 30, delay: 1400 },
      { step: `Semgrep found 23 candidates — running AI analysis…`, pct: 35, delay: 2200 },
    ];

    steps.forEach(({ step, pct, delay }) => {
      setTimeout(() => setProgress((p) => ({ ...p, step, pct })), delay);
    });

    MOCK_FINDINGS.forEach((finding, i) => {
      setTimeout(() => {
        setFindings((f) => [...f, finding]);
        setProgress({ step: `Analysing finding ${i + 1} of ${MOCK_FINDINGS.length}…`, pct: 35 + Math.round(((i + 1) / MOCK_FINDINGS.length) * 55), raw_count: 23 });
      }, 3000 + i * 900);
    });

    setTimeout(() => {
      setPhase("done");
      setProgress({ step: "Scan complete", pct: 100, raw_count: 23 });
    }, 3000 + MOCK_FINDINGS.length * 900 + 400);
  }, []);

  // REST polling driver — used when the WebSocket isn't available
  // (Vercel rewrites don't proxy WS; falls back to /scan/{id}/status polling).
  const pollScanProgress = useCallback(async (scanId) => {
    let lastDone = -1;
    while (true) {
      let s;
      try {
        const sRes = await fetch(`${API}/scan/${scanId}/status`);
        if (!sRes.ok) throw new Error(`status ${sRes.status}`);
        s = await sRes.json();
      } catch {
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }

      // progress is "{done}/{total} findings" once analyzing
      const m = (s.progress || "").match(/(\d+)\s*\/\s*(\d+)/);
      if (m) {
        const done = parseInt(m[1], 10);
        const total = parseInt(m[2], 10);
        if (done !== lastDone) {
          lastDone = done;
          setProgress({
            step: total === 0 || done === 0
              ? `Semgrep found ${total} candidates — running AI analysis…`
              : `Analysing finding ${done} of ${total}…`,
            pct: total ? 35 + Math.round((done / total) * 55) : 35,
            raw_count: total,
          });
        }
      } else if (s.status === "cloning") {
        setProgress({ step: "Cloning repository…", pct: 10, raw_count: 0 });
      } else if (s.status === "scanning") {
        setProgress({ step: "Running Semgrep…", pct: 25, raw_count: 0 });
      }

      if (s.status === "complete") {
        try {
          const fRes = await fetch(`${API}/findings/${scanId}`);
          const f = await fRes.json();
          setFindings(f.findings || []);
          setProgress({ step: "Scan complete", pct: 100, raw_count: f.raw_count });
          setPhase("done");
        } catch {
          /* leave UI as-is */
        }
        return;
      }
      if (s.status === "error") {
        setProgress({ step: `Error: ${s.error || "scan failed"}`, pct: 100, raw_count: 0 });
        setPhase("done");
        return;
      }

      await new Promise((r) => setTimeout(r, 2000));
    }
  }, []);

  // Rehydrate a session from a scan_id (used by ?scan=<id> on mount, by
  // back/forward navigation, and by handleScan when the backend returns an
  // existing scan for the same repo). Stale/unknown ids clear the URL and
  // drop back to idle.
  const rehydrateFromUrl = useCallback(async (scanId) => {
    if (!scanId) return;
    let f;
    try {
      const res = await fetch(`${API}/findings/${scanId}`);
      if (!res.ok) throw new Error(`status ${res.status}`);
      f = await res.json();
    } catch {
      writeScanIdToUrl(null);
      return;
    }
    currentScanIdRef.current = scanId;
    if (f.url) setRepoUrl(f.url);
    setFindings(f.findings || []);
    if (f.status === "complete") {
      setProgress({ step: "Scan complete", pct: 100, raw_count: f.raw_count });
      setPhase("done");
    } else if (f.status === "error") {
      setProgress({ step: `Error: ${f.error || "scan failed"}`, pct: 100, raw_count: f.raw_count });
      setPhase("done");
    } else {
      setPhase("scanning");
      setProgress({ step: "Resuming scan…", pct: 35, raw_count: f.raw_count });
      pollScanProgress(scanId);
    }
  }, [pollScanProgress]);

  const handleScan = useCallback(async ({ url, pat }) => {
    setRepoUrl(url);
    setUseMock(false);
    setPhase("scanning");
    setFindings([]);
    setProgress({ step: "Submitting…", pct: 5, raw_count: 0 });

    let scanId;
    let existing = false;
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, pat: pat || undefined }),
      });
      if (!res.ok) throw new Error(`scan failed: ${res.status}`);
      const data = await res.json();
      scanId = data.scan_id;
      existing = !!data.existing;
      // Latch onto this scan_id so stale broadcasts from earlier scans get
      // filtered out before scan_started arrives over the WebSocket.
      currentScanIdRef.current = scanId;
      writeScanIdToUrl(scanId);
    } catch {
      // backend unreachable — fall back to mock
      setUseMock(true);
      runMockScan(url);
      return;
    }

    if (existing) {
      // Backend deduped to a prior session for this repo — hydrate from it
      // directly; no scan_started event will fire because no new pipeline
      // ran.
      rehydrateFromUrl(scanId);
      return;
    }

    // If WS is connected, scan_started/finding_ready/scan_complete events
    // will drive the UI. Otherwise poll REST for progress.
    if (!connected) {
      pollScanProgress(scanId);
    }
  }, [connected, runMockScan, pollScanProgress, rehydrateFromUrl]);

  const handleReset = useCallback(() => {
    currentScanIdRef.current = null;
    writeScanIdToUrl(null);
    setPhase("idle");
    setFindings([]);
    setProgress({ step: "", pct: 0, raw_count: 0 });
    setRepoUrl("");
    setUseMock(false);
  }, []);

  useEffect(() => {
    rehydrateFromUrl(readScanIdFromUrl());
    const onPop = () => {
      const id = readScanIdFromUrl();
      if (id) rehydrateFromUrl(id);
      else handleReset();
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [rehydrateFromUrl, handleReset]);

  const exploitable = findings.filter((f) => f.exploitable);
  const suppressed = phase === "done" ? Math.max(0, progress.raw_count - exploitable.length) : 0;
  const escalations = findings.filter((f) => f.escalated_from);

  return (
    <div className="min-h-screen bg-[var(--bg)] grid-bg">
      <Header mode={useMock ? "demo" : connected ? "live" : "polling"} onHome={handleReset} />

      <main className="max-w-7xl mx-auto px-4 md:px-6 py-8 space-y-8">
        {/* Hero tagline */}
        {phase === "idle" && (
          <div className="text-center py-8 animate-fade-in-up">
            <p className="mono text-xs text-[var(--accent)] tracking-[0.3em] mb-3">// SECURITY ANALYSIS PIPELINE</p>
            <h1 className="text-4xl md:text-5xl font-black text-white leading-tight mb-3" style={{ fontFamily: "Syne, sans-serif" }}>
              Connect your repo.<br />
              <span className="text-[var(--accent)] text-glow">See why it's exploitable.</span>
            </h1>
            <p className="text-[var(--muted)] text-lg max-w-xl mx-auto">
              Semgrep detection + AI reasoning. Not just pattern matches —
              traced taint paths, real exploit steps, zero noise.
            </p>
          </div>
        )}

        {/* Scan form */}
        {phase === "idle" && (
          <div className="max-w-2xl mx-auto animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
            <ScanForm onScan={handleScan} scanning={false} />
          </div>
        )}

        {/* Scanning state */}
        {phase === "scanning" && (
          <ScanProgress
            progress={progress}
            findings={findings}
            repoUrl={repoUrl}
            useMock={useMock}
          />
        )}

        {/* Results */}
        {(phase === "done" || (phase === "scanning" && findings.length > 0)) && (
          <div className="space-y-6">
            {/* Stats bar */}
            {phase === "done" && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-fade-in-up">
                <StatCard label="Raw Findings" value={progress.raw_count} color="var(--muted)" />
                <StatCard label="Confirmed Exploitable" value={exploitable.length} color="var(--critical)" glow />
                <StatCard label="False Positives Filtered" value={suppressed} color="var(--low)" />
                <StatCard label="Severity Escalations" value={escalations.length} color="var(--medium)" />
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Findings list */}
              <div className="lg:col-span-2 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="mono text-xs text-[var(--muted)] tracking-widest uppercase">
                    {phase === "scanning" ? "Live Results" : `Confirmed Vulnerabilities (${exploitable.length})`}
                  </h2>
                  {phase === "done" && (
                    <button onClick={handleReset} className="mono text-xs text-[var(--accent)] hover:underline">
                      ← New Scan
                    </button>
                  )}
                </div>

                {findings.length === 0 ? (
                  <div className="border border-[var(--border)] rounded-lg p-8 text-center text-[var(--muted)] mono text-sm">
                    Waiting for first finding…
                  </div>
                ) : (
                  findings.map((f, i) => (
                    <FindingCard key={f.id ?? i} finding={f} index={i} />
                  ))
                )}
              </div>

              {/* Sidebar */}
              <div className="space-y-4">
                <RiskScore findings={findings} scanning={phase === "scanning"} />

                {phase === "done" && suppressed > 0 && (
                  <div className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg2)]">
                    <p className="mono text-xs text-[var(--muted)] tracking-widest mb-3 uppercase">Suppressed</p>
                    <p className="text-2xl font-black mono" style={{ color: "var(--low)" }}>{suppressed}</p>
                    <p className="mono text-xs text-[var(--muted)] mt-2">
                      findings Semgrep flagged but the reasoning model confirmed as non-exploitable.
                    </p>
                    <p className="mono text-xs text-[var(--muted)] mt-3 pt-3 border-t border-[var(--border)]">
                      Sanitization or framework-level protection confirmed. Not exploitable.
                    </p>
                  </div>
                )}

                {phase === "done" && (
                  <div className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg2)]">
                    <p className="mono text-xs text-[var(--muted)] tracking-widest mb-3 uppercase">Webhook</p>
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse-slow" />
                      <span className="mono text-xs text-[var(--accent)]">Registered on repo</span>
                    </div>
                    <p className="mono text-xs text-[var(--muted)] mt-2">
                      Every <span className="text-white">git push</span> will auto-trigger a rescan. Dashboard updates live.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {phase === "idle" && <EmptyState />}
      </main>
    </div>
  );
}

function StatCard({ label, value, color, glow }) {
  return (
    <div
      className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg2)] animate-fade-in-up"
      style={glow ? { boxShadow: `0 0 20px rgba(255,51,102,0.15)`, borderColor: "rgba(255,51,102,0.3)" } : {}}
    >
      <p className="mono text-xs text-[var(--muted)] tracking-wider mb-1">{label.toUpperCase()}</p>
      <p className="text-3xl font-black" style={{ color, fontFamily: "Space Mono, monospace" }}>{value}</p>
    </div>
  );
}