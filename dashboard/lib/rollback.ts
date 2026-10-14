// dashboard/lib/rollback.ts
// Deterministic best-effort inverse of a CLI change. Used when the AI is
// unavailable and as the default rollback for remediation requests. It is
// a starting point for a human to review, not a guarantee.
import { detectVendor } from './cisBenchmarks';

const PASS_THROUGH = /^(exit|end|configure( terminal)?|conf t|commit|top|up|quit|!|#)$/i;
const CONTEXT_HEADER = /^(interface |line |router |vlan |policy-map |class-map |ip access-list |control-plane|config |edit |user-interface |aaa$)/i;
const DESTRUCTIVE = /\b(reload|reboot|erase|zeroize|format|factory[- ]?reset)\b/i;

export function generateSmartRollback(cliCommand: string, vendorInput = 'generic'): string[] {
  const vendor = detectVendor(vendorInput);
  const lines = cliCommand.split('\n').map((l) => l.trim()).filter(Boolean);
  const out: string[] = [];

  for (const line of lines) {
    const lower = line.toLowerCase();

    if (DESTRUCTIVE.test(lower)) {
      out.push(`! Cannot be reversed from the CLI: "${line}"`);
      continue;
    }
    if (PASS_THROUGH.test(lower)) {
      out.push(line);
      continue;
    }

    if (vendor === 'juniper' || vendor === 'vyos') {
      if (lower.startsWith('set ')) out.push(`delete ${line.slice(4)}`);
      else if (lower.startsWith('delete ')) out.push(`set ${line.slice(7)}   ! restore the original value`);
      else out.push(`! Review manually: "${line}"`);
      continue;
    }

    if (vendor === 'fortinet') {
      if (CONTEXT_HEADER.test(lower) || lower === 'next') out.push(line);
      else if (lower.startsWith('set ')) out.push(`unset ${line.slice(4).split(/\s+/)[0]}   ! or set the previous value`);
      else if (lower.startsWith('unset ')) out.push(`set ${line.slice(6)} <previous value>`);
      else out.push(`! Review manually: "${line}"`);
      continue;
    }

    if (vendor === 'huawei') {
      if (CONTEXT_HEADER.test(lower)) out.push(line);
      else if (lower.startsWith('undo ')) out.push(line.slice(5));
      else out.push(`undo ${line}`);
      continue;
    }

    if (CONTEXT_HEADER.test(lower)) out.push(line);
    else if (lower.startsWith('no ')) out.push(line.slice(3).trim());
    else if (lower === 'shutdown') out.push('no shutdown');
    else out.push(`no ${line}`);
  }

  return out.length > 0 ? out : ['! Manual configuration inspection required for rollback.'];
}
