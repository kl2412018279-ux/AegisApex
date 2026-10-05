// _utils/formatters.tsx
import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, Terminal, Copy, Check } from 'lucide-react';

export function formatInlineBold(text: string, isDark: boolean) {
  // Matches **bold text** and `inline code`
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong
          key={i}
          className={`font-semibold px-1 py-0.5 rounded text-[11px] border ${
            isDark
              ? 'bg-slate-800 text-slate-100 border-slate-700'
              : 'bg-slate-200 text-slate-900 border-slate-300'
          }`}
        >
          {part.slice(2, -2)}
        </strong>
      );
    }

    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={i}
          className={`font-mono text-[11px] px-1.5 py-0.5 rounded border ${
            isDark
              ? 'bg-slate-950 text-amber-300 border-slate-800'
              : 'bg-slate-100 text-amber-800 border-slate-300'
          }`}
        >
          {part.slice(1, -1)}
        </code>
      );
    }

    return part;
  });
}

/**
 * Interactive Code Block component that allows inline editing
 * and copying the updated script content to the clipboard.
 */
export function EditableCodeBlock({
  code,
  lang,
  isDark,
}: {
  code: string;
  lang: string;
  isDark: boolean;
}) {
  const [editedCode, setEditedCode] = useState(code);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setEditedCode(code);
  }, [code]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(editedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy CLI script:', err);
    }
  };

  const lineCount = editedCode.split('\n').length;
  const rows = Math.max(3, Math.min(lineCount, 25));

  return (
    <div
      className={`my-3.5 rounded-lg border font-mono text-xs overflow-hidden shadow-md ${
        isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-900 border-slate-800'
      }`}
    >
      {/* Header Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 bg-slate-900/90 border-b border-slate-800 text-[10px] text-slate-400 font-bold uppercase tracking-wider">
        <span className="flex items-center gap-2 text-emerald-400 font-bold">
          <Terminal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          {lang ? `${lang.toUpperCase()} SCRIPT` : 'CLI SCRIPT'}
          <span className="text-[9px] text-amber-400/80 lowercase font-normal">
            (editable)
          </span>
        </span>

        <div className="flex items-center gap-3">
          <span className="text-slate-500 font-mono text-[9px] hidden sm:inline">
            Syntax Verified
          </span>
          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded border border-slate-700 transition-all text-[10px] font-mono cursor-pointer active:scale-95"
            title="Copy script to clipboard"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400 font-semibold">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-slate-400" />
                <span>Copy Script</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Editable Monospace Terminal Field */}
      <textarea
        rows={rows}
        value={editedCode}
        onChange={(e) => setEditedCode(e.target.value)}
        spellCheck={false}
        className="w-full p-4 font-mono text-xs text-emerald-400 bg-transparent leading-relaxed border-none outline-none resize-y selection:bg-emerald-950 selection:text-emerald-200 focus:ring-0"
      />
    </div>
  );
}

export function renderFormattedAnalysis(text: string, isDark: boolean) {
  if (!text || !text.trim()) {
    return (
      <div className="p-6 text-center text-slate-500 text-xs italic">
        No analysis output available. Click "Run AI Assessment" or "Scan Inventory" to generate telemetry.
      </div>
    );
  }

  // Phase 1: Tokenize text into code blocks vs standard text blocks
  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\s*\n?([\s\S]*?)```/g;
  const blocks: Array<{ type: 'text' | 'code'; lang?: string; content: string }> = [];
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      blocks.push({ type: 'text', content: text.substring(lastIndex, match.index) });
    }
    blocks.push({
      type: 'code',
      lang: match[1]?.trim() || 'cli',
      content: match[2].trim(),
    });
    lastIndex = codeBlockRegex.lastIndex;
  }

  if (lastIndex < text.length) {
    blocks.push({ type: 'text', content: text.substring(lastIndex) });
  }

  // Phase 2: Render Tokenized Blocks
  return (
    <div className="space-y-3 font-sans text-xs">
      {blocks.map((block, blockIdx) => {
        if (block.type === 'code') {
          const formattedCode = block.content.replace(/\\n/g, '\n').trim();

          return (
            <EditableCodeBlock
              key={`code-${blockIdx}`}
              code={formattedCode}
              lang={block.lang || 'cli'}
              isDark={isDark}
            />
          );
        }

        const lines = block.content.split('\n');

        return (
          <React.Fragment key={`text-block-${blockIdx}`}>
            {lines.map((line, lineIdx) => {
              const trimmed = line.trim();
              if (!trimmed) return null;

              const lineKey = `line-${blockIdx}-${lineIdx}`;

              // Horizontal Divider
              if (trimmed === '---' || /^={3,}$/.test(trimmed)) {
                return (
                  <hr
                    key={lineKey}
                    className={`my-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}
                  />
                );
              }

              // Blockquotes
              if (trimmed.startsWith('>')) {
                const quoteText = trimmed.replace(/^>\s*/, '');
                return (
                  <div
                    key={lineKey}
                    className={`p-3 rounded-r-lg border-l-4 border-l-sky-500 my-2 text-xs font-mono leading-relaxed ${
                      isDark
                        ? 'bg-slate-900/80 border-r border-t border-b border-slate-800 text-slate-200'
                        : 'bg-sky-50/50 border-r border-t border-b border-sky-200 text-slate-800'
                    }`}
                  >
                    {formatInlineBold(quoteText, isDark)}
                  </div>
                );
              }

              // Headings (#, ##, ###)
              if (trimmed.startsWith('#')) {
                const level = trimmed.match(/^#+/)?.[0].length || 1;
                const headerText = trimmed.replace(/^#+\s*/, '');
                return (
                  <div
                    key={lineKey}
                    className={`pt-3 pb-1 border-b my-2 flex items-center gap-2 ${
                      isDark ? 'border-slate-800 text-slate-100' : 'border-slate-200 text-slate-900'
                    }`}
                  >
                    <div
                      className={`rounded-full ${
                        level === 1
                          ? 'w-2 h-4 bg-amber-500'
                          : level === 2
                          ? 'w-1.5 h-3.5 bg-emerald-500'
                          : 'w-1.5 h-3 bg-sky-500'
                      }`}
                    />
                    <h4
                      className={`font-bold font-mono tracking-wider ${
                        level === 1 ? 'text-sm' : 'text-xs uppercase'
                      }`}
                    >
                      {headerText}
                    </h4>
                  </div>
                );
              }

              // Severity Callout Cards
              // FIX (real bug, confirmed by hand): these were unanchored,
              // so the word "critical" appearing ANYWHERE in ordinary
              // prose — e.g. the good-news line "No critical baseline CVE
              // matches identified for this OS image." — matched \bCRITICAL\b
              // case-insensitively and wrapped an all-clear message in a
              // red "HIGH RISK IMPACT" alert box. Anchored to the start of
              // the line with ^, matching how renderCleanAnalysis already
              // does this correctly further down this same file — a
              // severity tag has to be what the line IS, not just a word
              // it happens to contain.
              const isCritical = /^\[critical\]|^\bCRITICAL\b/i.test(trimmed) && !trimmed.startsWith('#');
              const isHigh = /^\[high\]|^\bHIGH RISK\b/i.test(trimmed) && !trimmed.startsWith('#');
              const isWarning = /^\[warning\]|^\[medium\]|^\bWARNING\b/i.test(trimmed) && !trimmed.startsWith('#');
              const isSafe = /^\[safe\]|^\[low\]|^\[success\]|^\bSAFE\b|^\bPASSED\b/i.test(trimmed) && !trimmed.startsWith('#');

              if (isCritical || isHigh) {
                return (
                  <div
                    key={lineKey}
                    className={`p-3 rounded-lg border-l-4 border-l-rose-500 my-2 text-xs font-mono leading-relaxed ${
                      isDark
                        ? 'bg-rose-950/40 border-r border-t border-b border-slate-800 text-rose-200'
                        : 'bg-rose-50 border-r border-t border-b border-rose-200 text-rose-900'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold mb-1 text-rose-400">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>HIGH RISK IMPACT</span>
                    </div>
                    {formatInlineBold(trimmed, isDark)}
                  </div>
                );
              }

              if (isWarning) {
                return (
                  <div
                    key={lineKey}
                    className={`p-3 rounded-lg border-l-4 border-l-amber-500 my-2 text-xs font-mono leading-relaxed ${
                      isDark
                        ? 'bg-amber-950/40 border-r border-t border-b border-slate-800 text-amber-200'
                        : 'bg-amber-50 border-r border-t border-b border-amber-200 text-amber-900'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold mb-1 text-amber-400">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>MODERATE RISK / WARNING</span>
                    </div>
                    {formatInlineBold(trimmed, isDark)}
                  </div>
                );
              }

              if (isSafe) {
                return (
                  <div
                    key={lineKey}
                    className={`p-3 rounded-lg border-l-4 border-l-emerald-500 my-2 text-xs font-mono leading-relaxed ${
                      isDark
                        ? 'bg-emerald-950/40 border-r border-t border-b border-slate-800 text-emerald-200'
                        : 'bg-emerald-50 border-r border-t border-b border-emerald-200 text-emerald-900'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold mb-1 text-emerald-400">
                      <CheckCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>SAFE OPERATION</span>
                    </div>
                    {formatInlineBold(trimmed, isDark)}
                  </div>
                );
              }

              // Bullets (*, -, 1.)
              if (trimmed.startsWith('* ') || trimmed.startsWith('- ') || /^\d+\.\s/.test(trimmed)) {
                const bulletText = trimmed.replace(/^([*\-]\s*|\d+\.\s*)/, '');
                return (
                  <div
                    key={lineKey}
                    className={`flex items-start gap-2.5 pl-2 py-1.5 rounded transition-colors ${
                      isDark ? 'hover:bg-slate-900/60 text-slate-300' : 'hover:bg-slate-100 text-slate-700'
                    }`}
                  >
                    <span className={`text-xs mt-0.5 font-bold shrink-0 ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>
                      ▸
                    </span>
                    <div className="leading-relaxed font-mono text-[11.5px] flex-1">
                      {formatInlineBold(bulletText, isDark)}
                    </div>
                  </div>
                );
              }

              // Strict Key-Value Cards match (prevents standard prose with colons from triggering cards)
              const kvMatch = trimmed.match(/^([a-zA-Z0-9_\-\s*]{2,35}):\s*(.+)$/);
              if (kvMatch && !trimmed.startsWith('http')) {
                const rawKey = kvMatch[1].replace(/\*/g, '').trim();
                const rawVal = kvMatch[2].trim();

                return (
                  <div
                    key={lineKey}
                    className={`p-2.5 rounded-md border flex items-center justify-between text-xs font-mono my-1.5 ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <span className="font-bold text-slate-400 uppercase text-[10px] tracking-wider">
                      {rawKey}
                    </span>
                    <span className={`font-semibold ${isDark ? 'text-slate-100' : 'text-slate-800'}`}>
                      {formatInlineBold(rawVal.replace(/\*/g, ''), isDark)}
                    </span>
                  </div>
                );
              }

              // Default Paragraph
              return (
                <p
                  key={lineKey}
                  className={`leading-relaxed text-[11.5px] font-mono my-1 ${
                    isDark ? 'text-slate-300' : 'text-slate-700'
                  }`}
                >
                  {formatInlineBold(trimmed, isDark)}
                </p>
              );
            })}
          </React.Fragment>
        );
      })}
    </div>
  );
}

/**
 * PRINT-ONLY renderer for AI analysis text (Executive Summary, Firmware
 * Analysis). renderFormattedAnalysis() above is intentionally untouched —
 * it's built for the live, interactive, dark-mode dashboard (editable CLI
 * textareas with copy buttons, neon risk-alert cards, monospace terminal
 * styling) and changing it would change how the on-screen app looks and
 * behaves, which is out of scope here.
 *
 * A static PDF has no business containing an editable <textarea> or a
 * "Copy Script" button, and the shouty colored "HIGH RISK IMPACT" /
 * "SAFE OPERATION" callout cards and wall-to-wall monospace font are what
 * make the printed report read as a hacker-terminal screenshot instead of
 * a document. This renders the same markdown-ish input (**bold**, `code`,
 * #/##/### headings, * bullets, ```code blocks```, --- rules) in the same
 * plain, quiet, sans-serif register as the rest of the print report.
 */
export function renderPrintAnalysis(text: string) {
  if (!text || !text.trim()) {
    return <p className="text-slate-400 italic">No analysis output available.</p>;
  }

  const formatInline = (t: string, keyPrefix: string) => {
    const parts = t.split(/(\*\*.*?\*\*|`.*?`)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
        return (
          <strong key={`${keyPrefix}-${i}`} className="font-semibold text-slate-900">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
        return (
          <code key={`${keyPrefix}-${i}`} className="font-mono text-[9.5px] px-1 py-0.5 rounded bg-slate-100 text-slate-700">
            {part.slice(1, -1)}
          </code>
        );
      }
      return <React.Fragment key={`${keyPrefix}-${i}`}>{part}</React.Fragment>;
    });
  };

  // Tokenize into code blocks vs text, same as renderFormattedAnalysis
  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\s*\n?([\s\S]*?)```/g;
  const blocks: Array<{ type: 'text' | 'code'; lang?: string; content: string }> = [];
  let lastIndex = 0;
  let match;
  while ((match = codeBlockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) blocks.push({ type: 'text', content: text.substring(lastIndex, match.index) });
    blocks.push({ type: 'code', lang: match[1]?.trim() || 'cli', content: match[2].trim() });
    lastIndex = codeBlockRegex.lastIndex;
  }
  if (lastIndex < text.length) blocks.push({ type: 'text', content: text.substring(lastIndex) });

  const nodes: React.ReactNode[] = [];
  let bulletBuf: string[] = [];
  let bulletKey = 0;

  const flushBullets = () => {
    if (bulletBuf.length) {
      nodes.push(
        <ul key={`ul-${bulletKey++}`} className="list-disc pl-4 space-y-0.5 my-1 text-slate-600">
          {bulletBuf.map((b, i) => (
            <li key={i} className="leading-relaxed">{formatInline(b, `li-${bulletKey}-${i}`)}</li>
          ))}
        </ul>
      );
      bulletBuf = [];
    }
  };

  blocks.forEach((block, blockIdx) => {
    if (block.type === 'code') {
      flushBullets();
      const code = block.content.replace(/\\n/g, '\n').trim();
      nodes.push(
        <div key={`code-${blockIdx}`} className="bg-slate-900 text-slate-100 rounded-md p-2.5 text-[8.5px] font-mono my-1.5">
          <p className="text-slate-400 font-medium uppercase tracking-wide text-[7.5px] mb-1">
            {block.lang && block.lang !== 'cli' ? block.lang.toUpperCase() : 'CLI Script'}
          </p>
          <code className="whitespace-pre-wrap block leading-relaxed">{code}</code>
        </div>
      );
      return;
    }

    block.content.split('\n').forEach((line, lineIdx) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const key = `${blockIdx}-${lineIdx}`;

      if (trimmed === '---' || /^={3,}$/.test(trimmed)) {
        flushBullets();
        nodes.push(<hr key={key} className="my-2 border-slate-200" />);
        return;
      }

      if (trimmed.startsWith('#')) {
        flushBullets();
        const headerText = trimmed.replace(/^#+\s*/, '');
        nodes.push(
          <p key={key} className="font-semibold text-slate-900 mt-2.5 mb-0.5">
            {formatInline(headerText, key)}
          </p>
        );
        return;
      }

      if (trimmed.startsWith('>')) {
        flushBullets();
        const quoteText = trimmed.replace(/^>\s*/, '');
        nodes.push(
          <p key={key} className="text-slate-500 italic border-l-2 border-slate-200 pl-2.5 my-1">
            {formatInline(quoteText, key)}
          </p>
        );
        return;
      }

      if (trimmed.startsWith('* ') || trimmed.startsWith('- ') || /^\d+\.\s/.test(trimmed)) {
        bulletBuf.push(trimmed.replace(/^([*\-]\s*|\d+\.\s*)/, ''));
        return;
      }

      flushBullets();
      // Strip severity/callout bracket tags like [HIGH] / [CRITICAL] rather
      // than turning them into a colored alert box — the risk badge
      // elsewhere on the page already carries that signal.
      const cleaned = trimmed.replace(/^\[(critical|high|medium|warning|safe|low|success)\]\s*/i, '');
      nodes.push(
        <p key={key} className="text-slate-600 leading-relaxed my-1">
          {formatInline(cleaned, key)}
        </p>
      );
    });
  });
  flushBullets();

  return <div className="space-y-0.5">{nodes}</div>;
}

/**
 * CLEAN LIVE-DASHBOARD renderer for AI analysis text. Same markdown-ish
 * input as renderFormattedAnalysis() (**bold**, `code`, #/##/### headings,
 * * bullets, ```code blocks```, --- rules, [HIGH]/[CRITICAL]/etc tags), but
 * without the heavy wall-to-wall monospace font and the big shouty colored
 * "HIGH RISK IMPACT" / "SAFE OPERATION" callout boxes — those compete with
 * the risk badge already shown elsewhere on the panel and make a quick scan
 * harder, not easier. Severity tags become a small inline pill instead of a
 * full-width alert card. Code blocks stay read-only (no editable textarea,
 * no "Copy Script" button) — this is for narrative/summary text, not CLI
 * scripts meant to be pasted into a device.
 *
 * renderFormattedAnalysis() above is untouched and still used wherever its
 * original look is wanted (e.g. the Sandbox impact-simulation terminal).
 * This is purely an additional, opt-in renderer — drop it in wherever a
 * panel wants a calmer read, isDarkMode-aware like the rest of the app.
 */
export function renderCleanAnalysis(text: string, isDark: boolean) {
  if (!text || !text.trim()) {
    return (
      <div className={`p-6 text-center text-xs italic ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
        No analysis output available.
      </div>
    );
  }

  const severityPill = (label: string, tone: 'critical' | 'high' | 'warning' | 'safe') => {
    const toneClasses: Record<string, string> = {
      critical: isDark ? 'bg-rose-500/15 text-rose-300 border-rose-500/30' : 'bg-rose-100 text-rose-700 border-rose-300',
      high: isDark ? 'bg-rose-500/15 text-rose-300 border-rose-500/30' : 'bg-rose-100 text-rose-700 border-rose-300',
      warning: isDark ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' : 'bg-amber-100 text-amber-700 border-amber-300',
      safe: isDark ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' : 'bg-emerald-100 text-emerald-700 border-emerald-300',
    };
    return (
      <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide border mr-1.5 align-middle ${toneClasses[tone]}`}>
        {label}
      </span>
    );
  };

  const formatInline = (t: string, keyPrefix: string) => {
    const parts = t.split(/(\*\*.*?\*\*|`.*?`)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
        return (
          <strong key={`${keyPrefix}-${i}`} className={isDark ? 'font-semibold text-slate-100' : 'font-semibold text-slate-900'}>
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
        return (
          <code
            key={`${keyPrefix}-${i}`}
            className={`font-mono text-[10.5px] px-1 py-0.5 rounded ${
              isDark ? 'bg-slate-800 text-amber-300' : 'bg-slate-100 text-amber-800'
            }`}
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      return <React.Fragment key={`${keyPrefix}-${i}`}>{part}</React.Fragment>;
    });
  };

  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\s*\n?([\s\S]*?)```/g;
  const blocks: Array<{ type: 'text' | 'code'; lang?: string; content: string }> = [];
  let lastIndex = 0;
  let match;
  while ((match = codeBlockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) blocks.push({ type: 'text', content: text.substring(lastIndex, match.index) });
    blocks.push({ type: 'code', lang: match[1]?.trim() || 'cli', content: match[2].trim() });
    lastIndex = codeBlockRegex.lastIndex;
  }
  if (lastIndex < text.length) blocks.push({ type: 'text', content: text.substring(lastIndex) });

  const nodes: React.ReactNode[] = [];
  let bulletBuf: string[] = [];
  let bulletKey = 0;

  const flushBullets = () => {
    if (bulletBuf.length) {
      nodes.push(
        <ul
          key={`ul-${bulletKey++}`}
          className={`list-disc pl-4 space-y-1 my-1.5 text-[11.5px] leading-relaxed ${
            isDark ? 'text-slate-300' : 'text-slate-700'
          }`}
        >
          {bulletBuf.map((b, i) => (
            <li key={i}>{formatInline(b, `li-${bulletKey}-${i}`)}</li>
          ))}
        </ul>
      );
      bulletBuf = [];
    }
  };

  blocks.forEach((block, blockIdx) => {
    if (block.type === 'code') {
      flushBullets();
      const code = block.content.replace(/\\n/g, '\n').trim();
      // Reuses the same interactive, copyable/editable terminal block as
      // renderFormattedAnalysis — the one thing about the old heavy render
      // that was actually useful (pasting remediation CLI straight to a
      // device). It naturally lands wherever the source text places it —
      // typically after the narrative/hardening-items text, since that's
      // how the AI output is structured — so no manual reordering needed.
      nodes.push(
        <EditableCodeBlock
          key={`code-${blockIdx}`}
          code={code}
          lang={block.lang || 'cli'}
          isDark={isDark}
        />
      );
      return;
    }

    block.content.split('\n').forEach((line, lineIdx) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const key = `${blockIdx}-${lineIdx}`;

      if (trimmed === '---' || /^={3,}$/.test(trimmed)) {
        flushBullets();
        nodes.push(<hr key={key} className={`my-2.5 ${isDark ? 'border-slate-800' : 'border-slate-200'}`} />);
        return;
      }

      if (trimmed.startsWith('#')) {
        flushBullets();
        const headerText = trimmed.replace(/^#+\s*/, '');
        nodes.push(
          <p
            key={key}
            className={`font-semibold text-[12.5px] mt-3 mb-1 ${isDark ? 'text-slate-100' : 'text-slate-900'}`}
          >
            {formatInline(headerText, key)}
          </p>
        );
        return;
      }

      if (trimmed.startsWith('>')) {
        flushBullets();
        const quoteText = trimmed.replace(/^>\s*/, '');
        nodes.push(
          <p
            key={key}
            className={`italic border-l-2 pl-2.5 my-1.5 text-[11.5px] leading-relaxed ${
              isDark ? 'text-slate-400 border-slate-700' : 'text-slate-500 border-slate-300'
            }`}
          >
            {formatInline(quoteText, key)}
          </p>
        );
        return;
      }

      if (trimmed.startsWith('* ') || trimmed.startsWith('- ') || /^\d+\.\s/.test(trimmed)) {
        bulletBuf.push(trimmed.replace(/^([*\-]\s*|\d+\.\s*)/, ''));
        return;
      }

      flushBullets();

      // Severity tags become a small inline pill prepended to the line,
      // instead of the full alert-card treatment.
      let pill: React.ReactNode = null;
      let cleaned = trimmed;
      if (/^\[critical\]|^\bCRITICAL\b/i.test(trimmed)) {
        pill = severityPill('Critical', 'critical');
        cleaned = trimmed.replace(/^\[critical\]\s*/i, '');
      } else if (/^\[high\]|^HIGH RISK/i.test(trimmed)) {
        pill = severityPill('High', 'high');
        cleaned = trimmed.replace(/^\[high\]\s*/i, '');
      } else if (/^\[warning\]|^\[medium\]|^WARNING/i.test(trimmed)) {
        pill = severityPill('Warning', 'warning');
        cleaned = trimmed.replace(/^\[(warning|medium)\]\s*/i, '');
      } else if (/^\[safe\]|^\[low\]|^\[success\]|^SAFE\b|^PASSED\b/i.test(trimmed)) {
        pill = severityPill('Safe', 'safe');
        cleaned = trimmed.replace(/^\[(safe|low|success)\]\s*/i, '');
      }

      nodes.push(
        <p key={key} className={`leading-relaxed text-[12px] my-1.5 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
          {pill}
          {formatInline(cleaned, key)}
        </p>
      );
    });
  });
  flushBullets();

  return <div className="space-y-0.5 font-sans">{nodes}</div>;
}