// dashboard/lib/groq.ts
// One place for the Groq chat-completions call, retry/fallback policy and
// JSON parsing that the scan, firmware and impact routes all use.

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

export const PRIMARY_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';
export const FALLBACK_MODEL = process.env.GROQ_FALLBACK_MODEL || 'llama-3.3-70b-versatile';

export interface GroqJsonRequest {
  system: string;
  user: string;
  temperature?: number;
  maxTokens?: number;
  timeoutMs?: number;
  label: string;
}

export interface GroqJsonResult<T> {
  data: T;
  model: string;
}

function stripFences(text: string): string {
  return text.replace(/```json/g, '').replace(/```/g, '').trim();
}

/**
 * Calls Groq expecting a JSON object back. Tries the primary model twice
 * (with back-off), then the fallback model. Returns null when no key is
 * configured or every attempt fails — callers must have a labelled fallback.
 */
export async function groqJson<T = Record<string, unknown>>(
  req: GroqJsonRequest,
  fetchImpl: typeof fetch = fetch
): Promise<GroqJsonResult<T> | null> {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return null;

  const attempts = [PRIMARY_MODEL, PRIMARY_MODEL, FALLBACK_MODEL];
  for (let i = 0; i < attempts.length; i++) {
    const model = attempts[i];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), req.timeoutMs ?? 20_000);
    try {
      const res = await fetchImpl(GROQ_URL, {
        method: 'POST',
        signal: controller.signal,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: req.system },
            { role: 'user', content: req.user },
          ],
          temperature: req.temperature ?? 0,
          // gpt-oss is a reasoning model: cap the hidden reasoning pass and
          // reserve output tokens, or it can return an empty JSON body.
          ...(model.startsWith('openai/gpt-oss') ? { reasoning_effort: 'low' } : {}),
          max_tokens: req.maxTokens ?? 2048,
          response_format: { type: 'json_object' },
        }),
      });
      if (res.ok) {
        const payload = await res.json();
        const content = stripFences(payload?.choices?.[0]?.message?.content || '');
        try {
          return { data: JSON.parse(content) as T, model };
        } catch {
          console.warn(`[!] Groq ${req.label} attempt ${i + 1} (${model}) returned non-JSON content`);
        }
      } else {
        const text = await res.text().catch(() => '');
        console.warn(`[!] Groq ${req.label} attempt ${i + 1} (${model}) returned ${res.status}: ${text.slice(0, 200)}`);
      }
    } catch (err) {
      console.warn(`[!] Groq ${req.label} attempt ${i + 1} (${model}) failed:`, err);
    } finally {
      clearTimeout(timer);
    }
    if (i < attempts.length - 1) await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
  }
  return null;
}
