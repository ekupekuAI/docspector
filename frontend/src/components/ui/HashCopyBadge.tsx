import React, { useState } from 'react';

interface HashCopyBadgeProps {
  hash: string;
  className?: string;
  label?: string;
  truncateLength?: number;
}

export const HashCopyBadge: React.FC<HashCopyBadgeProps> = ({
  hash,
  className = '',
  label = 'SHA-256',
  truncateLength,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API is not permitted
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const displayHash =
    truncateLength && hash && hash.length > truncateLength * 2
      ? `${hash.slice(0, truncateLength)}...${hash.slice(-truncateLength)}`
      : hash;

  return (
    <div className={`flex flex-col sm:flex-row sm:items-center gap-1.5 font-mono text-xs ${className}`}>
      {label && (
        <span className="text-slate-400 text-[11px] uppercase font-bold tracking-wider shrink-0">
          {label}:
        </span>
      )}
      <div className="flex items-center gap-2 max-w-full">
        <button
          type="button"
          onClick={handleCopy}
          className="group inline-flex items-center justify-between gap-2.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-slate-600 rounded text-slate-200 hover:text-white transition-all select-all focus:outline-none focus:ring-1 focus:ring-cyan-500 max-w-full"
          title={`Click to copy full SHA-256 cryptographic digest (${hash})`}
          aria-label={`Copy hash: ${hash}`}
        >
          <span className="font-mono text-[11.5px] tracking-wide break-all text-slate-300 group-hover:text-cyan-300 text-left">
            {displayHash}
          </span>
          <span
            className={`shrink-0 text-[11px] px-2 py-0.5 rounded font-mono font-medium transition-colors ${
              copied
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                : 'bg-slate-900 text-slate-400 group-hover:text-slate-200 border border-slate-700/80'
            }`}
          >
            {copied ? '✓ COPIED' : 'COPY'}
          </span>
        </button>
      </div>
    </div>
  );
};
