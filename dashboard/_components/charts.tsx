// dashboard/_components/charts.tsx
// Plain-SVG charts for the Trends tab.
//  * Risk is ordinal, so the risk mix uses ONE hue as a sequential ramp
//    (more severe = more prominent) rather than four status hues, which fail
//    adjacent-pair separation. Identity is never color-alone: legend labels,
//    2px gaps between stacked segments, a hover tooltip and a table view.
//  * Compliance is a single series: no legend; the card title names it.
import React, { useEffect, useRef, useState } from 'react';

export interface TrendPoint {
  date: string;
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  devicesTracked: number;
  compliancePct: number | null;
}

const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

// Tailwind red ramp; light mode darkens with severity, dark mode brightens.
const RAMP = {
  light: { LOW: '#fecaca', MEDIUM: '#f87171', HIGH: '#dc2626', CRITICAL: '#7f1d1d' },
  dark: { LOW: '#7f1d1d', MEDIUM: '#dc2626', HIGH: '#f87171', CRITICAL: '#fecaca' },
};

function useWidth<T extends HTMLElement>(): [React.RefObject<T>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(600);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(280, entry.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

const shortDate = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });

function ink(isDark: boolean) {
  return {
    grid: isDark ? '#1e293b' : '#e2e8f0',
    axis: isDark ? '#94a3b8' : '#64748b',
    surface: isDark ? '#0f172a' : '#ffffff',
    line: isDark ? '#818cf8' : '#4f46e5',
    tooltip: isDark ? 'bg-slate-950 border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900',
  };
}

/** Keep the first and last date labels inside the plot. */
function anchorFor(i: number, n: number): 'start' | 'middle' | 'end' {
  return n > 1 && i === 0 ? 'start' : n > 1 && i === n - 1 ? 'end' : 'middle';
}

function xTicks(points: TrendPoint[], max = 6): number[] {
  if (points.length <= max) return points.map((_, i) => i);
  const step = (points.length - 1) / (max - 1);
  return Array.from({ length: max }, (_, i) => Math.round(i * step));
}

export function RiskMixChart({ points, isDarkMode }: { points: TrendPoint[]; isDarkMode: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const c = ink(isDarkMode);
  const ramp = isDarkMode ? RAMP.dark : RAMP.light;
  const height = 220;
  const pad = { top: 8, right: 8, bottom: 24, left: 28 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const maxTotal = Math.max(1, ...points.map((p) => LEVELS.reduce((s, l) => s + p[l], 0)));
  const slot = plotW / Math.max(1, points.length);
  const barW = Math.max(2, Math.min(28, slot - 2));
  const y = (v: number) => pad.top + plotH - (v / maxTotal) * plotH;
  const yTicks = Array.from(new Set([0, Math.round(maxTotal / 2), maxTotal]));

  return (
    <div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 mb-2 text-[11px]" aria-label="Legend">
        {[...LEVELS].reverse().map((l) => (
          <li key={l} className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-3 rounded-sm" style={{ background: ramp[l] }} aria-hidden />
            {l.charAt(0) + l.slice(1).toLowerCase()}
          </li>
        ))}
      </ul>
      <div ref={ref} className="relative" onMouseLeave={() => setHover(null)}>
        <svg width={width} height={height} role="img" aria-label="Devices per risk level per day">
          {yTicks.map((t) => (
            <g key={t}>
              <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={c.grid} strokeWidth={1} />
              <text x={pad.left - 6} y={y(t) + 3} textAnchor="end" fontSize={10} fill={c.axis}>{t}</text>
            </g>
          ))}
          {points.map((p, i) => {
            const x = pad.left + i * slot + (slot - barW) / 2;
            let acc = 0;
            const segments = LEVELS.filter((l) => p[l] > 0);
            return (
              <g key={p.date} opacity={hover === null || hover === i ? 1 : 0.7}>
                {segments.map((l, si) => {
                  const y0 = y(acc);
                  acc += p[l];
                  const y1 = y(acc);
                  const isTop = si === segments.length - 1;
                  // 2px surface gap between stacked segments
                  const h = Math.max(0, y0 - y1 - (isTop ? 0 : 2));
                  return isTop ? (
                    <path key={l} fill={ramp[l]} d={`M${x},${y0} V${y1 + Math.min(4, h)} Q${x},${y1} ${x + Math.min(4, barW / 2)},${y1} H${x + barW - Math.min(4, barW / 2)} Q${x + barW},${y1} ${x + barW},${y1 + Math.min(4, h)} V${y0} Z`} />
                  ) : (
                    <rect key={l} x={x} y={y1 + 2} width={barW} height={h} fill={ramp[l]} />
                  );
                })}
                <rect x={pad.left + i * slot} y={pad.top} width={slot} height={plotH} fill="transparent" onMouseEnter={() => setHover(i)} />
              </g>
            );
          })}
          <line x1={pad.left} x2={width - pad.right} y1={y(0)} y2={y(0)} stroke={c.axis} strokeWidth={1} />
          {xTicks(points).map((i) => (
            <text key={i} x={pad.left + i * slot + slot / 2} y={height - 6} textAnchor={anchorFor(i, points.length)} fontSize={10} fill={c.axis}>{shortDate(points[i].date)}</text>
          ))}
        </svg>
        {hover !== null && points[hover] && (
          <div
            className={`absolute pointer-events-none z-10 rounded-lg border px-3 py-2 text-[11px] shadow-lg ${c.tooltip}`}
            style={{ left: Math.min(width - 150, Math.max(0, pad.left + hover * slot + slot / 2 - 70)), top: 0 }}
          >
            <div className="font-bold mb-1">{shortDate(points[hover].date)}</div>
            {[...LEVELS].reverse().map((l) => (
              <div key={l} className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: ramp[l] }} />{l}</span>
                <span className="font-mono">{points[hover][l]}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function ComplianceLine({ points, isDarkMode }: { points: TrendPoint[]; isDarkMode: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const c = ink(isDarkMode);
  const height = 180;
  const pad = { top: 10, right: 12, bottom: 24, left: 36 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const x = (i: number) => pad.left + (points.length <= 1 ? plotW / 2 : (i / (points.length - 1)) * plotW);
  const y = (v: number) => pad.top + plotH - (v / 100) * plotH;

  // Break the line where there is no data rather than inventing values.
  const segments: Array<Array<[number, number]>> = [];
  points.forEach((p, i) => {
    if (p.compliancePct === null) return segments.push([]);
    if (!segments.length) segments.push([]);
    segments[segments.length - 1].push([x(i), y(p.compliancePct)]);
  });
  const last = [...points].reverse().find((p) => p.compliancePct !== null);
  const lastIdx = last ? points.lastIndexOf(last) : -1;

  return (
    <div ref={ref} className="relative" onMouseLeave={() => setHover(null)}>
      <svg
        width={width}
        height={height}
        role="img"
        aria-label="Average CIS compliance percent per day"
        onMouseMove={(e) => {
          const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const i = Math.round(((e.clientX - rect.left - pad.left) / plotW) * (points.length - 1));
          setHover(i >= 0 && i < points.length ? i : null);
        }}
      >
        {[0, 50, 100].map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={c.grid} />
            <text x={pad.left - 6} y={y(t) + 3} textAnchor="end" fontSize={10} fill={c.axis}>{t}%</text>
          </g>
        ))}
        {segments.filter((s) => s.length).map((s, i) => (
          <polyline key={i} points={s.map(([a, b]) => `${a},${b}`).join(' ')} fill="none" stroke={c.line} strokeWidth={2} strokeLinejoin="round" />
        ))}
        {last && <circle cx={x(lastIdx)} cy={y(last.compliancePct!)} r={4} fill={c.line} stroke={c.surface} strokeWidth={2} />}
        {last && (
          <text x={Math.min(x(lastIdx), width - pad.right - 30)} y={y(last.compliancePct!) - 8} fontSize={10} fontWeight={700} fill={c.axis} textAnchor="middle">
            {last.compliancePct}%
          </text>
        )}
        {hover !== null && (
          <>
            <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + plotH} stroke={c.axis} strokeDasharray="3 3" />
            {points[hover].compliancePct !== null && <circle cx={x(hover)} cy={y(points[hover].compliancePct!)} r={4} fill={c.line} stroke={c.surface} strokeWidth={2} />}
          </>
        )}
        {xTicks(points).map((i) => (
          <text key={i} x={x(i)} y={height - 6} textAnchor={anchorFor(i, points.length)} fontSize={10} fill={c.axis}>{shortDate(points[i].date)}</text>
        ))}
      </svg>
      {hover !== null && points[hover] && (
        <div className={`absolute pointer-events-none rounded-lg border px-3 py-2 text-[11px] shadow-lg ${c.tooltip}`} style={{ left: Math.min(width - 140, Math.max(0, x(hover) - 60)), top: 0 }}>
          <div className="font-bold">{shortDate(points[hover].date)}</div>
          <div>{points[hover].compliancePct === null ? 'No config scans yet' : `${points[hover].compliancePct}% of rules passing`}</div>
        </div>
      )}
    </div>
  );
}

export function TrendTable({ points }: { points: TrendPoint[] }) {
  return (
    <table className="w-full text-[11px] font-mono">
      <thead>
        <tr className="text-left">
          <th className="py-1 pr-3">Date</th>
          {[...LEVELS].reverse().map((l) => <th key={l} className="py-1 pr-3">{l}</th>)}
          <th className="py-1 pr-3">Devices</th>
          <th className="py-1">Compliance</th>
        </tr>
      </thead>
      <tbody>
        {points.map((p) => (
          <tr key={p.date} className="border-t border-slate-500/20">
            <td className="py-1 pr-3">{p.date}</td>
            {[...LEVELS].reverse().map((l) => <td key={l} className="py-1 pr-3">{p[l]}</td>)}
            <td className="py-1 pr-3">{p.devicesTracked}</td>
            <td className="py-1">{p.compliancePct === null ? '—' : `${p.compliancePct}%`}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
