const API = "http://localhost:8000"; // swap for prod Vultr IP

// POST /scan → { scan_id }
export async function startScan(url, pat) {}

// GET /scan/:scanId/status → { status, progress }
export async function getStatus(scanId) {}

// GET /findings/:scanId → { raw_count, confirmed_count, findings[] }
export async function getFindings(scanId) {}
