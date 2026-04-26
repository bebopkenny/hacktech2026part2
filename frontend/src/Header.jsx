import React from "react";

export default function Header({ mode = "demo" }) {
  const indicator = {
    live:    { label: "LIVE",       color: "var(--low)",    glow: "0 0 8px rgba(52,211,153,0.8)" },
    polling: { label: "POLLING",    color: "var(--accent)", glow: "0 0 8px rgba(0,212,255,0.7)" },
    demo:    { label: "DEMO MODE",  color: "var(--muted)",  glow: null },
  }[mode] ?? { label: "DEMO MODE", color: "var(--muted)", glow: null };

  return (
    <header className="border-b border-[var(--border)] sticky top-0 z-50" style={{ backdropFilter: "blur(12px)", background: "rgba(6,8,16,0.9)" }}>
      <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative w-8 h-8 flex-shrink-0">
            <svg viewBox="0 0 32 32" fill="none" className="w-8 h-8">
              <polygon points="16,2 30,10 30,22 16,30 2,22 2,10" stroke="#00d4ff" strokeWidth="1.5" fill="none" />
              <polygon points="16,8 24,13 24,19 16,24 8,19 8,13" stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,0.08)" />
              <circle cx="16" cy="16" r="3" fill="#00d4ff" />
            </svg>
            <div className="absolute inset-0 animate-pulse-slow" style={{ background: "radial-gradient(circle, rgba(0,212,255,0.25) 0%, transparent 70%)" }} />
          </div>
          <span className="text-lg font-black tracking-widest text-white" style={{ fontFamily: "Syne, sans-serif", letterSpacing: "0.15em" }}>
            SENTINEL<span className="text-[var(--accent)]">AI</span>
          </span>
        </div>
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
