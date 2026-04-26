"""
Sends a finding + context bundle to the reasoning model and parses exploitability verdict.

analyze_finding(context_bundle) -> dict
  - builds a prompt with finding details + all file contents
  - calls K2-Think-v2 synchronously (sync so it works inside threading.Thread)
  - one retry on transient API errors or unparseable output, with a stricter prompt
  - strips <think>...</think> blocks (K2 emits chain-of-thought before the answer)
  - strips markdown fences and parses JSON response
  - returns: {exploitable, confidence, taint_path, auth_gap, exploit_steps, severity, fix}

K2-Think-v2 is reached via api.k2think.ai's OpenAI-compatible endpoint, so we use
the openai SDK pointed at K2_BASE_URL. K2 doesn't expose OpenAI's
`response_format=json_object` mode (and forcing it would suppress the <think>
block where the reasoning happens), so we ask for JSON in the prompt and
post-process.

Falls back to {exploitable: false, ...} if both attempts fail.
"""
import json
import logging
import os
import re

from openai import APIError, OpenAI

log = logging.getLogger("analyzer")

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            api_key=os.environ["K2_API_KEY"],
            base_url=os.getenv("K2_BASE_URL", "https://api.k2think.ai/v1"),
        )
    return _client


_MODEL = os.getenv("K2_MODEL", "MBZUAI-IFM/K2-Think-v2")


_PROMPT = """\
You are a security expert performing a code security review. Analyze the Semgrep finding below and the surrounding code to determine if it is actually exploitable.

## Finding
rule_id: {rule_id}
file: {file}
line: {line}
matched code: {matched_code}
semgrep message: {message}
{prior_block}
## Code Files
{files_block}

## Instructions
- Determine if this finding is exploitable: does attacker-controlled input reach a dangerous sink without adequate sanitization or auth checks?
- Cite specific file:line for every claim you make.
- Check whether the input is truly user-controlled (not from env vars, config, or other trusted sources).
- Check if existing middleware or auth already mitigates this path.
- Do NOT invent findings Semgrep didn't flag.

## Output format
You may reason briefly first, but you MUST end your response with the line `### ANSWER` on its own line, followed by a single JSON object matching this schema and nothing else:

{{
  "exploitable": true or false,
  "confidence": "high" or "medium" or "low",
  "taint_path": "source (file:line) → sink (file:line)" or null,
  "auth_gap": "description of missing auth check" or null,
  "exploit_steps": ["step1", "step2"],
  "severity": "critical" or "high" or "medium" or "low",
  "fix": "one-sentence fix description"
}}

Keep any reasoning under 300 words. The `### ANSWER` line and JSON object are required.
"""

_RETRY_NUDGE = (
    "\n\nIMPORTANT: Your previous response did not include a parseable JSON object after `### ANSWER`. "
    "Reply with at most 100 words of reasoning, then `### ANSWER` on its own line, then ONE JSON object matching the schema. "
    "No markdown fences, no text after the JSON."
)

_FALLBACK: dict = {
    "exploitable": False,
    "confidence": "low",
    "taint_path": None,
    "auth_gap": None,
    "exploit_steps": [],
    "severity": "low",
    "fix": "Review manually — AI analysis failed.",
}


def _extract_json(raw: str) -> dict | None:
    """Find the JSON object in K2's response.

    K2-Think-v2 narrates reasoning as plain prose (not <think> tags), so we
    look for an `### ANSWER` marker and parse what follows. Falls back to the
    LAST balanced {...} block in the response if no marker is present, and
    finally to scanning forward for any parseable {...}.
    """
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    cleaned = re.sub(r"```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()

    # Preferred path: split on `### ANSWER` (or `### Answer`, or just `ANSWER:`).
    marker = re.search(r"###\s*ANSWER\s*\n?|^ANSWER:\s*", cleaned, flags=re.IGNORECASE | re.MULTILINE)
    if marker:
        cleaned = cleaned[marker.end():].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Fallback: try every balanced {...} from the END of the string backwards
    # (the JSON usually comes after the prose).
    starts = [i for i, ch in enumerate(cleaned) if ch == "{"]
    for start in reversed(starts):
        depth = 0
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start : i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def _call_k2(prompt: str) -> str:
    client = _get_client()
    response = client.chat.completions.create(
        model=_MODEL,
        max_tokens=4096,
        temperature=0.2,
        stream=False,
        messages=[{"role": "user", "content": prompt}],
    )
    return (response.choices[0].message.content or "").strip()


def analyze_finding(context_bundle: dict, prior_context: str = "") -> dict:
    finding = context_bundle["finding"]
    files = context_bundle["files"]

    files_block = "\n\n".join(
        f"### {path}\n```\n{content[:3000]}\n```"
        for path, content in files.items()
    )

    prior_block = ""
    if prior_context:
        prior_block = (
            "\n## Prior scan context for this repo\n"
            "Memory of previous scans (use this to flag recurring findings):\n"
            f"{prior_context}\n"
        )

    prompt = _PROMPT.format(
        rule_id=finding.get("check_id", "unknown"),
        file=finding.get("path", "unknown"),
        line=finding.get("start", {}).get("line", 0),
        matched_code=finding.get("extra", {}).get("lines", ""),
        message=finding.get("extra", {}).get("message", ""),
        files_block=files_block,
        prior_block=prior_block,
    )

    for attempt in (1, 2):
        try:
            raw = _call_k2(prompt)
        except APIError as e:
            log.warning("K2 API error on attempt %d: %s", attempt, e)
            if attempt == 2:
                return _FALLBACK.copy()
            continue

        parsed = _extract_json(raw)
        if parsed is not None:
            return parsed

        log.warning("K2 response unparseable on attempt %d: %r", attempt, raw[:200])
        prompt = prompt + _RETRY_NUDGE

    return _FALLBACK.copy()
