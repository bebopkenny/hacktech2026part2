"""
Sends a finding + context bundle to the reasoning model and parses exploitability verdict.

analyze_finding(context_bundle) -> dict
  - builds a prompt with finding details + all file contents
  - calls Claude synchronously (sync so it works inside threading.Thread)
  - strips markdown fences and parses JSON response
  - returns: {exploitable, confidence, taint_path, auth_gap, exploit_steps, severity, fix}

Prompt instructs the model to:
  - cite specific file:line for every claim
  - check if input is actually user-controlled
  - check if sanitization/auth middleware already covers this
  - NOT invent findings Semgrep didn't flag
  - respond with ONLY valid JSON (no prose)

Falls back to {exploitable: false, ...} if response can't be parsed.
"""
import json
import os
import re

import anthropic

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _client


_PROMPT = """\
You are a security expert performing a code security review. Analyze the Semgrep finding below and the surrounding code to determine if it is actually exploitable.

## Finding
rule_id: {rule_id}
file: {file}
line: {line}
matched code: {matched_code}
semgrep message: {message}

## Code Files
{files_block}

## Instructions
- Determine if this finding is exploitable: does attacker-controlled input reach a dangerous sink without adequate sanitization or auth checks?
- Cite specific file:line for every claim you make.
- Check whether the input is truly user-controlled (not from env vars, config, or other trusted sources).
- Check if existing middleware or auth already mitigates this path.
- Do NOT invent findings Semgrep didn't flag.
- Respond with ONLY valid JSON — no prose, no markdown fences.

## Required JSON schema
{{
  "exploitable": true or false,
  "confidence": "high" or "medium" or "low",
  "taint_path": "source (file:line) → sink (file:line)" or null,
  "auth_gap": "description of missing auth check" or null,
  "exploit_steps": ["step1", "step2"],
  "severity": "critical" or "high" or "medium" or "low",
  "fix": "one-sentence fix description"
}}
"""

_FALLBACK: dict = {
    "exploitable": False,
    "confidence": "low",
    "taint_path": None,
    "auth_gap": None,
    "exploit_steps": [],
    "severity": "low",
    "fix": "Review manually — AI analysis failed.",
}


def analyze_finding(context_bundle: dict) -> dict:
    finding = context_bundle["finding"]
    files = context_bundle["files"]

    files_block = "\n\n".join(
        f"### {path}\n```\n{content[:3000]}\n```"
        for path, content in files.items()
    )

    prompt = _PROMPT.format(
        rule_id=finding.get("check_id", "unknown"),
        file=finding.get("path", "unknown"),
        line=finding.get("start", {}).get("line", 0),
        matched_code=finding.get("extra", {}).get("lines", ""),
        message=finding.get("extra", {}).get("message", ""),
        files_block=files_block,
    )

    client = _get_client()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    raw = re.sub(r"^```[a-z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return _FALLBACK.copy()
