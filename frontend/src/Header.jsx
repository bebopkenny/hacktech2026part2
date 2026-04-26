import React from "react";

export default function Header({ mode = "demo", onHome }) {
  const indicator = {
    live:    { label: "LIVE",       color: "var(--low)",    glow: "0 0 8px rgba(52,211,153,0.8)" },
    polling: { label: "POLLING",    color: "var(--accent)", glow: "0 0 8px rgba(0,212,255,0.7)" },
    demo:    { label: "DEMO MODE",  color: "var(--muted)",  glow: null },
  }[mode] ?? { label: "DEMO MODE", color: "var(--muted)", glow: null };

  return (
    <header className="border-b border-[var(--border)] sticky top-0 z-50" style={{ backdropFilter: "blur(12px)", background: "rgba(6,8,16,0.9)" }}>
      <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex items-center justify-between">
        <button
          type="button"
          onClick={onHome}
          aria-label="pira.tech home"
          className="flex items-center gap-3 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded"
        >
          <div className="relative w-8 h-8 flex-shrink-0">
            {/* Jolly Roger — skull and crossed cutlasses */}
            <svg viewBox="0 0 32 32" fill="none" className="w-8 h-8">
              {/* crossed cutlasses */}
              <line x1="5" y1="5" x2="27" y2="27" stroke="#00d4ff" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="27" y1="5" x2="5" y2="27" stroke="#00d4ff" strokeWidth="1.5" strokeLinecap="round" />
              {/* skull */}
              <path d="M16 7c-4.4 0-7.5 2.9-7.5 7 0 2.3 1 4.1 2.5 5.2v2.3c0 .8.7 1.5 1.5 1.5h1v-2h2v2h1v-2h2v2h1c.8 0 1.5-.7 1.5-1.5v-2.3c1.5-1.1 2.5-2.9 2.5-5.2 0-4.1-3.1-7-7.5-7z" fill="#0a1020" stroke="#00d4ff" strokeWidth="1.3" />
              {/* eye sockets */}
              <circle cx="13" cy="14" r="1.6" fill="#00d4ff" />
              <circle cx="19" cy="14" r="1.6" fill="#00d4ff" />
              {/* nose / teeth gap */}
              <path d="M15.3 17l.7-1.2.7 1.2-.7.8z" fill="#00d4ff" />
            </svg>
            <div className="absolute inset-0 animate-pulse-slow" style={{ background: "radial-gradient(circle, rgba(0,212,255,0.25) 0%, transparent 70%)" }} />
          </div>
          <span className="text-lg font-black tracking-widest text-white" style={{ fontFamily: "Syne, sans-serif", letterSpacing: "0.15em" }}>
            PIRA<span className="text-[var(--accent)]">.TECH</span>
          </span>
        </button>
        <div className="flex items-center gap-4 md:gap-6">
          <div className="hidden md:flex items-center gap-4 mono text-xs text-[var(--muted)]">
            <span>SEMGREP</span>
            <span className="w-px h-3 bg-[var(--border)]" />
            <span>JS + PY</span>
            <span className="w-px h-3 bg-[var(--border)]" />
            <span>OWASP TOP 10</span>
          </div>
          <div className="flex items-center gap-2 mono text-xs">
            <span
              className="w-2 h-2 rounded-full flex-shrink-0"
              style={{ backgroundColor: indicator.color, ...(indicator.glow ? { boxShadow: indicator.glow } : {}) }}
            />
            <span style={{ color: indicator.color }}>{indicator.label}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
