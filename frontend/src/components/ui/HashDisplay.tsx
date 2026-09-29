import React, { useState } from 'react';

interface HashDisplayProps {
  hash: string;
  label?: string;
}

export const HashDisplay: React.FC<HashDisplayProps> = ({ hash, label = 'SHA-256' }) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const displayHash =
    expanded || !hash || hash.length <= 24
      ? hash
      : `${hash.slice(0, 16)}...${hash.slice(-8)}`;

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
      <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
        <span>{label}</span>
        <button
          type="button"
          onClick={handleCopy}
          className="text-[10px] px-2 py-0.5 rounded border border-slate-200 bg-white hover:bg-slate-100 text-slate-600 transition"
        >
          {copied ? '✓ COPIED' : 'COPY'}
        </button>
      </div>
      <div className="mt-2 break-all font-mono text-xs text-slate-800 font-semibold select-all">
        {displayHash}
      </div>
      {hash && hash.length > 24 && (
        <button
          type="button"
          onClick={() => setExpanded((val) => !val)}
          className="mt-2 text-[11px] font-medium text-blue-600 hover:text-blue-700 font-sans"
        >
          {expanded ? 'Hide full hash' : 'View full hash'}
        </button>
      )}
    </div>
  );
};
