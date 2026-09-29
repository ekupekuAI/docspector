import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface AccessDeniedProps {
  message?: string;
}

export const AccessDenied: React.FC<AccessDeniedProps> = ({
  message = 'Access denied: you do not have permission to view or manage this evidence scope.',
}) => {
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-red-800 shadow-sm flex items-start gap-3">
      <ShieldAlert className="h-5 w-5 text-red-600 shrink-0 mt-0.5" />
      <div>
        <div className="font-semibold text-sm text-red-900">Access Restricted</div>
        <div className="mt-1 text-xs text-red-700 font-sans leading-relaxed">{message}</div>
      </div>
    </div>
  );
};
