//dashboard\_components\SandboxTab.tsx
import React, { useState } from 'react';
import { Terminal as TerminalIcon, RefreshCw, Play, Trash2, Copy, Check } from 'lucide-react';
import { renderFormattedAnalysis } from '../_utils/formatters';

interface SandboxTabProps {
  isDarkMode: boolean;
  proposedCommand: string;
  setProposedCommand: (cmd: string) => void;
  analyzingCommand: boolean;
  sandboxAnalysis: string;
  handleAnalyzeCommand: (e: React.FormEvent) => void;
}

export function SandboxTab({
  isDarkMode,
  proposedCommand,
  setProposedCommand,
  analyzingCommand,
  sandboxAnalysis,
  handleAnalyzeCommand,
}: SandboxTabProps) {
  const [copied, setCopied] = useState(false);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      if (proposedCommand.trim() && !analyzingCommand) {
        handleAnalyzeCommand(e as any);
      }
    }
  };

  const handleCopyAnalysis = () => {
    if (!sandboxAnalysis) return;
    navigator.clipboard.writeText(sandboxAnalysis);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const presetButtonClass = `px-2.5 py-1 text-[10px] font-mono rounded border transition-all cursor-pointer ${
    isDarkMode
      ? 'bg-slate-800/80 hover:bg-slate-700 text-slate-300 border-slate-700/70 hover:border-slate-600'
      : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-300'
  }`;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Input Panel */}
      <div
        className={`rounded-xl border p-5 flex flex-col h-[650px] ${
          isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
        }`}
      >
        <div
          className={`flex items-center justify-between pb-3 border-b mb-4 shrink-0 ${
            isDarkMode ? 'border-slate-800' : 'border-slate-200'
          }`}
        >
          <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-amber-500" />
            <h3 className="font-bold text-sm">Propose CLI Remediation Command</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">Dry-Run Mode</span>
        </div>

        <form onSubmit={handleAnalyzeCommand} className="flex-1 flex flex-col space-y-4">
          <p className={`text-xs ${isDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>
            Input proposed CLI commands to simulate syntax validity, impact blast radius, and rollback requirements against active configurations.
          </p>

          <div className="flex-1 relative flex flex-col">
            <textarea
              value={proposedCommand}
              onChange={(e) => setProposedCommand(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={`e.g.\nno ip http server\nline vty 0 15\n transport input ssh\n exec-timeout 10 0`}
              className={`w-full flex-1 p-3.5 pr-10 font-mono text-xs rounded-lg border outline-none resize-none transition-all leading-relaxed ${
                isDarkMode
                  ? 'bg-slate-950 border-slate-800 text-slate-200 focus:border-amber-500/50'
                  : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-amber-500'
              }`}
            />
            {proposedCommand && (
              <button
                type="button"
                onClick={() => setProposedCommand('')}
                className="absolute top-2.5 right-2.5 p-1 rounded hover:bg-slate-500/20 text-slate-400 hover:text-slate-200 transition-colors"
                title="Clear input"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Quick Preset Buttons */}
          <div className="space-y-2">
            <span className="text-[10px] font-mono uppercase font-bold text-slate-500">
              Quick Presets
            </span>
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setProposedCommand('no ip http server\nno ip http secure-server')}
                className={presetButtonClass}
              >
                + Disable HTTP Services
              </button>
              <button
                type="button"
                onClick={() => setProposedCommand('line vty 0 15\n transport input ssh\n exec-timeout 15 0')}
                className={presetButtonClass}
              >
                + Secure VTY SSH
              </button>
              <button
                type="button"
                onClick={() => setProposedCommand('no service telnet\nno service pad')}
                className={presetButtonClass}
              >
                + Hardened Legacy Protocols
              </button>
              <button
                type="button"
                onClick={() => setProposedCommand('interface Ethernet1/1\n shutdown')}
                className={presetButtonClass}
              >
                + Interface Shutdown
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-[10px] font-mono text-slate-500">
              Press <kbd className="px-1 py-0.5 bg-slate-800 text-slate-300 rounded text-[9px]">Cmd+Enter</kbd> to execute
            </span>

            <button
              type="submit"
              disabled={analyzingCommand || !proposedCommand.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:bg-slate-800/50 disabled:text-slate-500 text-white font-bold rounded-lg text-xs transition-all shadow-sm cursor-pointer disabled:cursor-not-allowed"
            >
              {analyzingCommand ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Simulating Impact...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Impact Analysis</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Output Terminal Panel */}
      <div
        className={`rounded-xl border flex flex-col h-[650px] overflow-hidden ${
          isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
        }`}
      >
        <div
          className={`p-3.5 border-b flex items-center justify-between ${
            isDarkMode ? 'border-slate-800 bg-slate-950/40' : 'border-slate-200 bg-slate-50'
          }`}
        >
          <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-emerald-500" />
            <span
              className={`font-mono text-xs font-bold uppercase tracking-wider ${
                isDarkMode ? 'text-slate-300' : 'text-slate-700'
              }`}
            >
              CLI Command Impact Simulation Terminal
            </span>
          </div>

          <div className="flex items-center gap-2">
            {analyzingCommand && (
              <span className="flex items-center gap-1.5 text-[10px] font-mono text-amber-500 mr-2">
                <RefreshCw className="w-3 h-3 animate-spin" />
                Evaluating CLI...
              </span>
            )}
            {sandboxAnalysis && (
              <button
                onClick={handleCopyAnalysis}
                className="flex items-center gap-1 px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-mono transition-colors border border-slate-700 cursor-pointer"
                title="Copy full analysis text"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-slate-400" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Formatted Output Canvas */}
        <div className="flex-1 p-5 overflow-y-auto bg-slate-950 text-slate-200 leading-relaxed rounded-b-xl border-t border-slate-900 text-xs">
          {sandboxAnalysis ? (
            <div className="prose prose-invert max-w-none space-y-3 font-sans">
              {renderFormattedAnalysis(sandboxAnalysis, true)}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-6 space-y-2">
              <TerminalIcon className="w-8 h-8 text-slate-600 mb-1" />
              <p className="font-semibold text-slate-400 text-xs">Impact Simulation Terminal Ready</p>
              <p className="text-[11px] text-slate-500 max-w-sm">
                Enter proposed CLI commands on the left and click{' '}
                <strong className="text-amber-500 font-bold">"Run Impact Analysis"</strong> (or press{' '}
                <kbd className="px-1 py-0.5 bg-slate-800 text-slate-300 rounded font-mono text-[9px]">
                  Cmd+Enter
                </kbd>
                ) to simulate execution risks.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}