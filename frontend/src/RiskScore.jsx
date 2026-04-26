import React, { useMemo } from "react";

const SEV_WEIGHT = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2, INFO: 0 };

function computeScore(findings) {
  const exploitable = findings.filter((f) => f.exploitable);
  if (exploitable.length === 0) return 0;
  const raw = exploitable.reduce((acc, f) => acc + (SEV_WEIGHT[f.severity?.toUpperCase()] || 0), 0);
  return Math.min(100, raw);
}

function scoreLabel(score) {
  if (score >= 80) return { text: "CRITICAL RISK", color: "var(--critical)" };
  if (score >= 50) return { text: "HIGH RISK", color: "var(--high)" };
  if (score >= 25) return { text: "MEDIUM RISK", color: "var(--medium)" };
  if (score > 0) return { text: "LOW RISK", color: "var(--low)" };
  return { text: "NO FINDINGS", color: "var(--muted)" };
}

export default function RiskScore({ findings, scanning }) {
  const score = useMemo(() => computeScore(findings), [findings]);
  const { text, color } = scoreLabel(score);

  // SVG ring
  const r = 40;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);

  const bySev = useMemo(() => {
    const map = {};
    findings.filter((f) => f.exploitable).forEach((f) => {
      const s = f.severity?.toUpperCase() || "INFO";
      map[s] = (map[s] || 0) + 1;
    });
    return map;
  }, [findings]);

  return (
    <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg2)]">
      <p className="mono text-xs text-[var(--muted)] tracking-widest mb-4 uppercase">Risk Score</p>

      {/* Ring */}
      <div className="flex flex-col items-center mb-5">
        <div className="relative w-28 h-28">
          <svg className="w-full h-full" viewBox="0 0 100 100">
            {/* Track */}
            <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="8" />
            {/* Progress */}
            <circle
              cx="50" cy="50" r={r}
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={offset}
              className="risk-ring transition-all duration-700"
              style={{ filter: `drop-shadow(0 0 6px ${color})` }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="mono text-2xl font-bold" style={{ color }}>{score}</span>
            <span className="mono text-xs text-[var(--muted)]">/100</span>
          </div>
        </div>
        <span className="mono text-xs font-bold mt-2" style={{ color }}>{text}</span>
        {scanning && (
          <span className="mono text-xs text-[var(--muted)] mt-1 animate-pulse-slow">updating…</span>
        )}
      </div>

      {/* Breakdown */}
      {Object.keys(bySev).length > 0 && (
        <div className="space-y-2 border-t border-[var(--border)] pt-4">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) =>
            bySev[s] ? (
              <div key={s} className="flex items-center justify-between">
                <span className={"mono text-xs px-2 py-0.5 rounded " + `badge-${s.toLowerCase()}`}>{s}</span>
                <span className="mono text-sm font-bold text-white">{bySev[s]}</span>
              </div>
            ) : null
          )}
        </div>
      )}

      {findings.length === 0 && !scanning && (
        <p className="mono text-xs text-[var(--muted)] text-center">Awaiting scan</p>
      )}
    </div>
  );
}
