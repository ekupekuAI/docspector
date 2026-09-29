import React from 'react';

interface MetricCardProps {
  label: string;
  value: string;
  detail?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({ label, value, detail }) => {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-soft card-interactive">
      <p className="text-sm font-semibold uppercase tracking-wide text-slate-600 font-sans">{label}</p>
      <div className="mt-3 flex items-end justify-between gap-3">
        <span className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 font-sans">{value}</span>
      </div>
      {detail ? <p className="mt-2.5 text-sm text-slate-500 font-sans leading-relaxed">{detail}</p> : null}
    </div>
  );
};
