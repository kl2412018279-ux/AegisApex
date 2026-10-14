// dashboard/lib/http.ts
import { NextResponse } from 'next/server';
import { ZodError } from 'zod';

export class HttpError extends Error {
  constructor(public status: number, message: string, public headers?: Record<string, string>) {
    super(message);
  }
}

/** Converts anything thrown inside a route handler into a JSON response. */
export function routeError(err: unknown, context: string): NextResponse {
  if (err instanceof HttpError) {
    return NextResponse.json({ success: false, error: err.message }, { status: err.status, headers: err.headers });
  }
  if (err instanceof ZodError) {
    const issues = err.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`);
    return NextResponse.json({ success: false, error: `Invalid request — ${issues.join('; ')}` }, { status: 400 });
  }
  console.error(`[-] ${context}:`, err);
  return NextResponse.json({ success: false, error: 'Internal Server Error' }, { status: 500 });
}

export async function readJson(req: Request): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, 'Invalid JSON request body');
  }
}

export function clientIp(req: Request): string | null {
  const fwd = req.headers.get('x-forwarded-for');
  return fwd ? fwd.split(',')[0].trim() : req.headers.get('x-real-ip');
}
