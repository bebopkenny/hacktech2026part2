import React, { useState } from "react";

const SEV_COLOR = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
};

const SEV_CSS = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

export default function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(index === 0);

  const sev = finding.severity?.toUpperCase() || "INFO";
  const colorClass = SEV_COLOR[sev] || "info";
  const badgeClass = SEV_CSS[sev] || "badge-info";

  return (
    <div
      className={"finding-card rounded-lg overflow-hidden bg-[var(--bg2)] border border-[var(--border)] " + colorClass}
      style={{ animationDelay: `${index * 0.08}s`, opacity: 0, animationFillMode: "forwards" }}
    >
      {/* Card header */}
      <button
        className="w-full text-left p-4 flex items-start gap-3 hover:bg-white/[0.02] transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Severity badge */}
        <span className={"mono text-xs font-bold px-2 py-1 rounded flex-shrink-0 " + badgeClass}>
          {sev}
        </span>

        {/* Title */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="mono text-xs text-white font-bold truncate">
              {finding.rule_id?.split(".").pop()?.replace(/-/g, " ").toUpperCase() || "UNKNOWN RULE"}
            </span>
            {finding.escalated_from && (
              <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: "rgba(251,191,36,0.15)", color: "var(--medium)", border: "1px solid rgba(251,191,36,0.3)" }}>
                ↑ {finding.escalated_from} → {sev}
              </span>
            )}
            {!finding.exploitable && (
              <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: "rgba(52,211,153,0.1)", color: "var(--low)", border: "1px solid rgba(52,211,153,0.2)" }}>
                NOT EXPLOITABLE
              </span>
            )}
          </div>
          <p className="mono text-xs text-[var(--muted)] mt-1">
            {finding.file}:{finding.line}
          </p>
        </div>

        {/* Expand icon */}
        <svg
          className={"w-4 h-4 text-[var(--muted)] flex-shrink-0 transition-transform mt-0.5 " + (expanded ? "rotate-180" : "")}
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Matched code snippet */}
      {finding.matched_code && (
        <div className="px-4 pb-3 -mt-1">
          <div className="code-block text-[var(--muted)]">
            <span className="text-[var(--border)]">// {finding.file}:{finding.line}</span>
            {"\n"}
            <span className="text-[var(--accent)]">{finding.matched_code}</span>
          </div>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-[var(--border)] px-4 py-4 space-y-4 animate-fade-in-up">
          {/* Exploitability verdict */}
          <Section
            label="EXPLOITABLE"
            icon={finding.exploitable ? "⚠" : "✓"}
            iconColor={finding.exploitable ? "var(--critical)" : "var(--low)"}
          >
            <span className={"mono text-sm font-bold " + (finding.exploitable ? "text-[var(--critical)]" : "text-[var(--low)]")}>
              {finding.exploitable ? "YES" : "NO"}
            </span>
            {finding.confidence && (
              <span className="mono text-xs text-[var(--muted)] ml-2">confidence: {finding.confidence}</span>
            )}
          </Section>

          {/* Taint path */}
          {finding.taint_path && (
            <Section label="TAINT PATH" icon="→" iconColor="var(--accent)">
              <p className="mono text-xs text-[var(--text)] leading-relaxed">{finding.taint_path}</p>
            </Section>
          )}

          {/* Auth gap */}
          {finding.auth_gap && (
            <Section label="AUTH ASSESSMENT" icon="🔐" iconColor="var(--medium)">
              <p className="mono text-xs text-[var(--text)] leading-relaxed">{finding.auth_gap}</p>
            </Section>
          )}

          {/* Exploit steps */}
          {finding.exploit_steps?.length > 0 && (
            <Section label="EXPLOIT PATH" icon="⚡" iconColor="var(--critical)">
              <ol className="space-y-1.5">
                {finding.exploit_steps.map((step, i) => (
                  <li key={i} className="flex gap-2 mono text-xs text-[var(--text)]">
                    <span className="text-[var(--critical)] flex-shrink-0">{i + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </Section>
          )}

          {/* Fix */}
          {finding.fix && (
            <Section label="RECOMMENDED FIX" icon="🛠" iconColor="var(--low)">
              <p className="mono text-xs text-[var(--text)] leading-relaxed">{finding.fix}</p>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ label, icon, iconColor, children }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2">
        <span style={{ color: iconColor }}>{icon}</span>
        <span className="mono text-xs text-[var(--muted)] tracking-widest">{label}</span>
      </div>
      <div className="pl-4 border-l border-[var(--border)]">{children}</div>
    </div>
  );
}
