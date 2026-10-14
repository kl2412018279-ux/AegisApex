// dashboard/_hooks/jobWatcher.ts
// Waits for an agent job to finish. Uses Supabase Realtime (the migration
// adds agent_jobs to the publication) and falls back to a slow poll in case
// Realtime is disabled on the project.
import { supabase } from '@/lib/supabase';

export interface JobOutcome {
  status: 'succeeded' | 'failed' | 'timeout';
  error?: string | null;
}

const FINAL = new Set(['succeeded', 'failed', 'cancelled']);

export function watchJob(jobId: string, onDone: (outcome: JobOutcome) => void, timeoutMs = 10 * 60_000): () => void {
  let finished = false;
  const finish = (outcome: JobOutcome) => {
    if (finished) return;
    finished = true;
    cleanup();
    onDone(outcome);
  };
  const handle = (row: { status?: string; error?: string | null } | null) => {
    if (row?.status && FINAL.has(row.status)) finish({ status: row.status === 'succeeded' ? 'succeeded' : 'failed', error: row.error });
  };

  const channel = supabase
    .channel(`job-${jobId}`)
    .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'agent_jobs', filter: `id=eq.${jobId}` }, (payload) => handle(payload.new as never))
    .subscribe();

  const poll = setInterval(async () => {
    const { data } = await supabase.from('agent_jobs').select('status, error').eq('id', jobId).maybeSingle();
    handle(data);
  }, 10_000);
  const timer = setTimeout(() => finish({ status: 'timeout' }), timeoutMs);

  function cleanup() {
    clearInterval(poll);
    clearTimeout(timer);
    supabase.removeChannel(channel);
  }
  return () => {
    finished = true;
    cleanup();
  };
}
