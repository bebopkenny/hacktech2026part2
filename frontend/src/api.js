const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export async function startScan(url, pat) {
  const res = await fetch(`${API}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, pat: pat || null }),
  });
  if (!res.ok) throw new Error(`scan failed: ${res.status}`);
  return res.json(); // { scan_id }
}

export async function getStatus(scanId) {
  const res = await fetch(`${API}/scan/${scanId}/status`);
  if (!res.ok) throw new Error(`status failed: ${res.status}`);
  return res.json(); // { status, progress, error }
}

export async function getFindings(scanId) {
  const res = await fetch(`${API}/findings/${scanId}`);
  if (!res.ok) throw new Error(`findings failed: ${res.status}`);
  return res.json(); // { scan_id, status, raw_count, confirmed_count, findings[] }
}

export async function pollUntilDone(scanId, onTick) {
  while (true) {
    const s = await getStatus(scanId);
    onTick?.(s);
    if (s.status === "complete" || s.status === "error") return s;
    await new Promise((r) => setTimeout(r, 2000));
  }
}
