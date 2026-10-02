// dashboard/app/impact-analysis/page.tsx
'use client';

import React, { useState } from 'react';
import {
  Terminal,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  Play,
  FileCode,
} from 'lucide-react';

interface DangerousCommand {
  command: string;
  reason: string;
  severity: string;
}

interface ImpactAnalysisResult {
  risk_score: number;
  risk_level: string;
  blast_radius: string;
  syntax_valid: boolean;
  service_impact_summary: string;
  dangerous_commands: DangerousCommand[];
  rollback_commands: string[];
  raw_markdown?: string;
}

export default function ImpactAnalysisPage() {
  const [deviceId, setDeviceId] = useState('');
  const [proposedCli, setProposedCli] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImpactAnalysisResult | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault();
    if (!proposedCli.trim()) {
      setError('Please provide proposed CLI commands to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/analyze-impact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: deviceId.trim(),
          deviceId: deviceId.trim(),
          proposed_cli: proposedCli,
          proposedCommand: proposedCli,
          activeConfig: '',
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to simulate configuration impact.');
      }

      // Handle direct structured response vs wrapped endpoint response
      if (data.risk_score !== undefined || data.service_impact_summary) {
        setResult({
          risk_score: data.risk_score ?? 50,
          risk_level: data.risk_level || 'MEDIUM',
          blast_radius: data.blast_radius || 'Configuration-level scope',
          syntax_valid: data.syntax_valid ?? true,
          service_impact_summary: data.service_impact_summary || 'Analysis complete.',
          dangerous_commands: data.dangerous_commands || [],
          rollback_commands: Array.isArray(data.rollback_commands) ? data.rollback_commands : [],
          raw_markdown: data.raw_markdown,
        });
      } else if (data.success && data.impactSummary) {
        const riskLevel = data.suggestedAction?.riskLevel || 'MEDIUM';
        const riskScoreMap: Record<string, number> = {
          Critical: 90,
          High: 70,
          Medium: 50,
          Low: 20,
          Informational: 10,
        };

        const rollbackArr = data.suggestedAction?.rollback
          ? Array.isArray(data.suggestedAction.rollback)
            ? data.suggestedAction.rollback
            : [data.suggestedAction.rollback]
          : [];

        setResult({
          risk_score: riskScoreMap[riskLevel] || 50,
          risk_level: riskLevel,
          blast_radius: data.blastRadius || 'Target device routing & interface domain',
          syntax_valid: data.syntaxValid ?? true,
          service_impact_summary: data.impactSummary,
          dangerous_commands:
            riskLevel === 'Critical' || riskLevel === 'High'
              ? [
                  {
                    command: data.suggestedAction?.command || proposedCli.split('\n')[0] || 'Target command',
                    reason: data.suggestedAction?.rationale || 'High-risk operational state shift detected.',
                    severity: riskLevel,
                  },
                ]
              : [],
          rollback_commands: rollbackArr,
          raw_markdown: data.suggestedAction?.rationale || data.impactSummary,
        });
      } else {
        throw new Error(data.error || 'Invalid analysis response returned by server.');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'An unexpected error occurred during analysis.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  function handleCopyRollback() {
    if (!result?.rollback_commands?.length) return;
    navigator.clipboard.writeText(result.rollback_commands.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function getRiskBadgeColor(level: string) {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 border-red-500/30 text-red-400';
      case 'HIGH':
        return 'bg-orange-500/10 border-orange-500/30 text-orange-400';
      case 'MEDIUM':
        return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
      case 'LOW':
      case 'INFORMATIONAL':
        return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
      default:
        return 'bg-slate-500/10 border-slate-500/30 text-slate-400';
    }
  }

  return (
    <div className="mx-auto max-w-6xl p-6 text-slate-100">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Terminal className="w-6 h-6 text-amber-400" />
            Pre-Change Impact Sandbox
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Simulate CLI command impact against active configurations to prevent operational outages before deployment.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Input Form Panel */}
        <form onSubmit={handleAnalyze} className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="mb-4">
              <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Target Device ID <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                type="text"
                value={deviceId}
                disabled={loading}
                onChange={(e) => setDeviceId(e.target.value)}
                placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm font-mono text-slate-200 outline-none focus:border-blue-500 disabled:opacity-50"
              />
            </div>

            <div className="mb-4">
              <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Proposed CLI Changes <span className="text-red-400">*</span>
              </label>
              <textarea
                rows={10}
                value={proposedCli}
                disabled={loading}
                onChange={(e) => setProposedCli(e.target.value)}
                placeholder={`router bgp 65001\n no neighbor 192.168.1.1 shutdown\n interface GigabitEthernet0/1\n shutdown`}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm font-mono text-slate-200 outline-none focus:border-blue-500 disabled:opacity-50"
              />
            </div>

            {error && (
              <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || !proposedCli.trim()}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-blue-600 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed cursor-pointer shadow-md"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Simulating Blast Radius...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Run Pre-Change Impact Simulation</span>
              </>
            )}
          </button>
        </form>

        {/* Output Panel */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <h2 className="mb-4 text-lg font-semibold text-slate-200 flex items-center gap-2">
              <FileCode className="w-5 h-5 text-blue-400" />
              Simulation Output
            </h2>

            {!result && !loading && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-slate-800 text-xs text-slate-500 text-center p-6">
                Submit proposed CLI commands on the left panel to execute full blast-radius safety analysis.
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-64 text-xs text-blue-400 gap-3">
                <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
                <span>Evaluating configuration semantics, syntax & automated rollback strategies...</span>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                {/* Metric Summary Bar */}
                <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <div>
                    <span className="text-xs text-slate-400 font-mono">Risk Score</span>
                    <div className="text-2xl font-bold font-mono text-white">{result.risk_score} / 100</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${
                        result.syntax_valid
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          : 'bg-red-500/10 border-red-500/30 text-red-400'
                      }`}
                    >
                      {result.syntax_valid ? 'Syntax Valid' : 'Syntax Error'}
                    </span>
                    <span className={`rounded-md border px-3 py-1 text-xs font-bold ${getRiskBadgeColor(result.risk_level)}`}>
                      {result.risk_level}
                    </span>
                  </div>
                </div>

                {/* Scope & Blast Radius */}
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs">
                  <span className="font-semibold text-slate-300">Blast Radius Scope:</span>
                  <p className="mt-1 text-slate-400 font-mono">{result.blast_radius}</p>
                </div>

                {/* Service Impact Summary */}
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs">
                  <span className="font-semibold text-slate-300">Service Impact Assessment:</span>
                  <p className="mt-1 text-slate-300 leading-relaxed">{result.service_impact_summary}</p>
                </div>

                {/* High Risk Command Warnings */}
                {result.dangerous_commands?.length > 0 && (
                  <div>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      High-Risk Operations Detected
                    </h3>
                    <div className="space-y-2">
                      {result.dangerous_commands.map((item, idx) => (
                        <div key={idx} className="rounded-lg border border-red-900/40 bg-red-950/20 p-2.5 text-xs">
                          <div className="font-mono text-red-300 font-semibold">{item.command}</div>
                          <div className="mt-1 text-slate-400">{item.reason}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Generated Rollback Script */}
                {result.rollback_commands?.length > 0 && (
                  <div>
                    <div className="mb-2 flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Automated Rollback Plan
                      </h3>
                      <button
                        onClick={handleCopyRollback}
                        className="text-xs text-slate-400 hover:text-slate-200 transition flex items-center gap-1 cursor-pointer"
                      >
                        {copied ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Script</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs font-mono text-emerald-300 leading-relaxed">
                      {result.rollback_commands.join('\n')}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}