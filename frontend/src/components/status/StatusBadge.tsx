import React from 'react';

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const toneMap: Record<string, { bg: string; text: string; dot: string }> = {
  VALID: { bg: 'bg-emerald-50', text: 'text-emerald-800 border border-emerald-300 font-semibold', dot: 'bg-emerald-500' },
  STORED: { bg: 'bg-emerald-50', text: 'text-emerald-800 border border-emerald-300 font-semibold', dot: 'bg-emerald-500' },
  VERIFIED: { bg: 'bg-emerald-50', text: 'text-emerald-800 border border-emerald-300 font-semibold', dot: 'bg-emerald-500' },
  APPROVED: { bg: 'bg-emerald-50', text: 'text-emerald-800 border border-emerald-300 font-semibold', dot: 'bg-emerald-500' },
  ACTIVE: { bg: 'bg-blue-50', text: 'text-blue-800 border border-blue-300 font-semibold', dot: 'bg-blue-500' },
  OPEN: { bg: 'bg-blue-50', text: 'text-blue-800 border border-blue-300 font-semibold', dot: 'bg-blue-500' },
  PENDING: { bg: 'bg-amber-50', text: 'text-amber-800 border border-amber-300 font-semibold', dot: 'bg-amber-500' },
  RESTRICTED: { bg: 'bg-red-100', text: 'text-red-900 border-2 border-red-600 font-bold tracking-wide shadow-sm', dot: 'bg-red-600' },
  REJECTED: { bg: 'bg-red-50', text: 'text-red-800 border border-red-300 font-semibold', dot: 'bg-red-500' },
  INTEGRITY_FAILURE: { bg: 'bg-red-100', text: 'text-red-900 border-2 border-red-600 font-bold tracking-wide shadow-sm', dot: 'bg-red-600' },
  REVOKED: { bg: 'bg-slate-100', text: 'text-slate-800 border border-slate-300 font-semibold', dot: 'bg-slate-500' },
  CLOSED: { bg: 'bg-slate-100', text: 'text-slate-800 border border-slate-300 font-semibold', dot: 'bg-slate-500' },
  RESOLVED: { bg: 'bg-emerald-50', text: 'text-emerald-800 border border-emerald-300 font-semibold', dot: 'bg-emerald-500' },
  DEFAULT: { bg: 'bg-slate-100', text: 'text-slate-800 border border-slate-300 font-semibold', dot: 'bg-slate-500' },
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  const tone = toneMap[status.toUpperCase()] ?? toneMap.DEFAULT;

  return (
    <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs sm:text-sm ${tone.bg} ${tone.text} ${className}`}>
      <span className={`h-2 w-2 rounded-full ${tone.dot} shrink-0`} />
      <span>{status}</span>
    </span>
  );
};
