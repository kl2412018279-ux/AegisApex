// dashboard/_components/ui.tsx
// Small shared building blocks for the newer tabs, matching the existing
// slate/emerald look and the isDarkMode prop convention.
import React from 'react';
import { getRiskColor } from '../_utils/riskHelpers';

export function Card({ isDarkMode, className = '', children }: { isDarkMode: boolean; className?: string; children: React.ReactNode }) {
  return (
    <section className={`rounded-xl border p-5 ${isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'} ${className}`}>
      {children}
    </section>
  );
}

export function CardTitle({ icon: Icon, children, right }: { icon?: React.ElementType; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 mb-4">
      <h3 className="flex items-center gap-2 font-bold text-sm">
        {Icon && <Icon className="w-4 h-4 text-slate-400" aria-hidden />}
        {children}
      </h3>
      {right}
    </div>
  );
}

export function RiskBadge({ level, isDarkMode }: { level?: string | null; isDarkMode: boolean }) {
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getRiskColor(level || 'UNASSESSED', isDarkMode).badge}`}>
      {level || 'UNASSESSED'}
    </span>
  );
}

type ButtonTone = 'primary' | 'danger' | 'neutral' | 'success';

const TONES: Record<ButtonTone, string> = {
  primary: 'bg-blue-600 hover:bg-blue-500 border-blue-500 text-white',
  danger: 'bg-rose-700 hover:bg-rose-600 border-rose-600 text-white',
  success: 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white',
  neutral: '',
};

export function Button({
  tone = 'neutral',
  isDarkMode,
  className = '',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: ButtonTone; isDarkMode: boolean }) {
  const neutral = isDarkMode ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200' : 'bg-white hover:bg-slate-50 border-slate-300 text-slate-800';
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
        tone === 'neutral' ? neutral : TONES[tone]
      } ${className}`}
    />
  );
}

export function inputClass(isDarkMode: boolean): string {
  return `w-full rounded-lg border px-3 py-2 text-xs ${
    isDarkMode ? 'bg-slate-950 border-slate-700 text-slate-100 placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-900 placeholder:text-slate-400'
  } focus:outline-none focus:ring-2 focus:ring-emerald-500/50`;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-slate-500 py-6 text-center">{children}</p>;
}

export function muted(isDarkMode: boolean): string {
  return isDarkMode ? 'text-slate-400' : 'text-slate-600';
}
