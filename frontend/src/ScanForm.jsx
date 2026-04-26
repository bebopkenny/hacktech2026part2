import React, { useState } from "react";

export default function ScanForm({ onScan, scanning }) {
  const [url, setUrl] = useState("");
  const [pat, setPat] = useState("");
  const [showPat, setShowPat] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url.trim() || scanning) return;
    onScan({ url: url.trim(), pat: pat.trim() });
  };

  const isValid = url.includes("github.com/");

  return (
    <div
      className="border border-[var(--border)] rounded-lg p-6"
      style={{ background: "linear-gradient(135deg, rgba(0,212,255,0.04) 0%, rgba(12,16,32,0.95) 100%)" }}
    >
      <div className="flex items-center gap-2 mb-5">
        <div className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse-slow" />
        <span className="mono text-xs text-[var(--muted)] tracking-widest">BOARD A REPO</span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* URL */}
        <div>
          <label className="block mono text-xs text-[var(--muted)] mb-2 tracking-wider">GITHUB REPOSITORY URL — DROP ANCHOR</label>
          <div className="relative">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="cyber-input w-full rounded px-4 py-3 mono text-sm pr-10"
              disabled={scanning}
            />
            {isValid && (
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                <svg className="w-4 h-4 text-[var(--low)]" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
              </div>
            )}
          </div>
        </div>

        {/* PAT toggle */}
        <div>
          <button
            type="button"
            onClick={() => setShowPat(!showPat)}
            className="flex items-center gap-2 mono text-xs text-[var(--muted)] hover:text-[var(--accent)] transition-colors"
          >
            <svg className={"w-3 h-3 transition-transform " + (showPat ? "rotate-90" : "")} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            PRIVATE REPO? ADD PERSONAL ACCESS TOKEN
          </button>
          {showPat && (
            <div className="mt-3 animate-fade-in-up">
              <input
                type="password"
                value={pat}
                onChange={(e) => setPat(e.target.value)}
                placeholder="ghp_xxxxxxxxxxxx"
                className="cyber-input w-full rounded px-4 py-3 mono text-sm"
                disabled={scanning}
              />
              <p className="mt-1 mono text-xs text-[var(--muted)]">
                Requires <span className="text-[var(--accent)]">repo</span> +{" "}
                <span className="text-[var(--accent)]">admin:repo_hook</span> scope
              </p>
            </div>
          )}
        </div>

        {/* Submit */}
        <button type="submit" disabled={!url.trim() || scanning} className="cyber-btn w-full rounded py-3 text-sm flex items-center justify-center gap-3">
          {scanning ? (
            <>
              <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              PLUNDERING…
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-.175-.005-.349-.015-.52A8.002 8.002 0 0020.488 7" />
              </svg>
              SET SAIL — RUN SECURITY ANALYSIS
            </>
          )}
        </button>
      </form>
    </div>
  );
}
