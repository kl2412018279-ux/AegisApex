// dashboard/_utils/impactMarkdown.ts
// /api/analyze-impact already returns complete Markdown (metrics, analysis,
// rollback script); the sandbox only adds which device it was run against.
export function buildImpactMarkdown(data: { analysis?: string; aiUnavailable?: boolean }, hostname: string, vendor: string): string {
  const header = `> **Target Device:** \`${hostname || 'Device'}\` (${(vendor || 'generic').toUpperCase()})${
    data.aiUnavailable ? ' · ⚠️ AI unavailable — keyword-based floor only' : ''
  }\n\n`;
  return header + (data.analysis || '_No analysis returned._');
}
