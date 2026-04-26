import React from "react";

const DEMO_REPOS = [
  { name: "vulnerable-node", url: "https://github.com/cr0hn/vulnerable-node", desc: "Node.js · SQL injection, XSS, insecure auth" },
  { name: "DVWA-node", url: "https://github.com/appsecco/dvna", desc: "Express · OWASP Top 10 coverage" },
  { name: "flask-vulnerable", url: "https://github.com/we45/Vulnerable-Flask-App", desc: "Python Flask · injection, IDOR" },
];

export default function EmptyState() {
  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
      {/* How it works */}
      <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg2)]">
        <p className="mono text-xs text-[var(--muted)] tracking-widest mb-4 uppercase">How It Works</p>
        <div className="space-y-3">
          {[
            { n: "01", label: "Semgrep scan", desc: "Deterministic pattern detection — p/owasp-top-ten, p/secrets, p/sql-injection" },
            { n: "02", label: "AI context analysis", desc: "Reasoning model traces taint paths across files, checks auth middleware, filters false positives" },
            { n: "03", label: "Confirmed findings only", desc: "Only exploitable vulnerabilities surface, with file/line evidence and step-by-step exploit path" },
            { n: "04", label: "Webhook auto-rescan", desc: "Every git push triggers a new scan. Dashboard updates live — no developer action needed" },
          ].map(({ n, label, desc }) => (
            <div key={n} className="flex gap-4">
              <span className="mono text-xs text-[var(--accent)] flex-shrink-0 pt-0.5">{n}</span>
              <div>
                <p className="mono text-xs text-white font-bold">{label}</p>
                <p className="mono text-xs text-[var(--muted)] mt-0.5">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Demo repos */}
      <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg2)]">
        <p className="mono text-xs text-[var(--muted)] tracking-widest mb-4 uppercase">Demo Repos</p>
        <div className="space-y-2">
          {DEMO_REPOS.map((r) => (
            <div key={r.name} className="flex items-center justify-between gap-2 p-2 rounded hover:bg-white/5 transition-colors">
              <div>
                <p className="mono text-xs text-white">{r.name}</p>
                <p className="mono text-xs text-[var(--muted)]">{r.desc}</p>
              </div>
              <button
                onClick={() => navigator.clipboard?.writeText(r.url)}
                className="mono text-xs text-[var(--accent)] flex-shrink-0 hover:underline"
                title="Copy URL"
              >
                copy url
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
