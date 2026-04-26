import React from "react";

export default function ScanProgress({ progress, findings, repoUrl, useMock }) {
  const shortUrl = repoUrl.replace("https://github.com/", "");

  return (
    <div className="space-y-4 animate-fade-in-up">
      {/* Repo banner */}
      <div className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg2)] flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <svg className="w-4 h-4 text-[var(--accent)] flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
          </svg>
          <span className="mono text-sm text-white truncate">{shortUrl || repoUrl}</span>
        </div>
        {useMock && (
          <span className="mono text-xs text-[var(--medium)] border border-[var(--medium)] border-opacity-30 rounded px-2 py-0.5 flex-shrink-0" style={{ background: "rgba(251,191,36,0.08)" }}>
            DEMO DATA
          </span>
        )}
      </div>

      {/* Progress bar */}
      <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg2)]">
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs text-[var(--muted)]">{progress.step}</span>
          <span className="mono text-xs text-[var(--accent)]">{progress.pct}%</span>
        </div>
        <div className="h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full progress-bar transition-all duration-500"
            style={{ width: `${progress.pct}%` }}
          />
        </div>

        {/* Pipeline stages */}
        <div className="flex items-center gap-0 mt-4">
          {[
            { label: "CLONE", done: progress.pct >= 15 },
            { label: "SEMGREP", done: progress.pct >= 35 },
            { label: "AI ANALYSIS", done: progress.pct >= 90 },
            { label: "FILTER", done: progress.pct >= 100 },
          ].map((stage, i, arr) => (
            <React.Fragment key={stage.label}>
              <div className="flex flex-col items-center">
                <div
                  className={"w-2.5 h-2.5 rounded-full transition-all duration-300 " + (stage.done ? "bg-[var(--accent)]" : "bg-[var(--border)]")}
                  style={stage.done ? { boxShadow: "0 0 8px rgba(0,212,255,0.6)" } : {}}
                />
                <span className={"mono text-xs mt-1 " + (stage.done ? "text-[var(--accent)]" : "text-[var(--border)]")}>
                  {stage.label}
                </span>
              </div>
              {i < arr.length - 1 && (
                <div className={"flex-1 h-px mx-1 " + (stage.done ? "bg-[var(--accent)]" : "bg-[var(--border)]")} style={{ marginBottom: "14px" }} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Live count */}
      {findings.length > 0 && (
        <div className="flex items-center gap-3 mono text-sm text-[var(--muted)]">
          <div className="w-2 h-2 rounded-full bg-[var(--critical)] animate-pulse-slow" style={{ boxShadow: "0 0 8px rgba(255,51,102,0.8)" }} />
          <span>
            <span className="text-white font-bold">{findings.filter((f) => f.exploitable).length}</span> confirmed exploitable
            {progress.raw_count > 0 && (
              <span className="ml-2 text-[var(--border)]">({progress.raw_count} raw candidates)</span>
            )}
          </span>
        </div>
      )}
    </div>
  );
}
