// dashboard/lib/deviceView.ts
// What the browser is allowed to see of a devices row. Works with whatever
// columns the table has, so a project whose schema differs a little from
// ours (e.g. device_type instead of vendor) still gets its inventory.

const HIDDEN = /(^|_)(pass|password|passwd|secret|token|private_key|api_key)($|_)|^enable_|^ssh_host_key$/i;

export function publicDevice(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    if (!HIDDEN.test(key)) out[key] = value;
  }
  return out;
}
