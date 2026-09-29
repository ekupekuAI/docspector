import React from 'react';
import { Button } from './Button';

interface StateProps {
  title?: string;
  description?: string;
  className?: string;
}

export const LoadingState: React.FC<StateProps> = ({
  title = 'Loading records...',
  description = 'Connecting to Docspector custody verification service...',
  className = '',
}) => (
  <div className={`flex flex-col items-center justify-center p-12 text-center rounded-md border border-slate-800/80 bg-slate-900/30 ${className}`}>
    <div className="w-8 h-8 border-2 border-slate-400 border-t-slate-100 rounded-full animate-spin mb-4" />
    <h4 className="text-sm font-semibold text-slate-200 tracking-tight">{title}</h4>
    <p className="mt-1 text-xs text-slate-400 max-w-sm">{description}</p>
  </div>
);

interface EmptyStateProps extends StateProps {
  actionLabel?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No records found',
  description = 'There are no active records in this view.',
  actionLabel,
  onAction,
  icon,
  className = '',
}) => (
  <div className={`flex flex-col items-center justify-center p-12 text-center rounded-md border border-slate-800/60 bg-slate-950/60 ${className}`}>
    <div className="text-2xl text-slate-500 mb-3 select-none">
      {icon || '🗂'}
    </div>
    <h4 className="text-sm font-semibold text-slate-200 tracking-tight">{title}</h4>
    <p className="mt-1 text-xs text-slate-400 max-w-sm">{description}</p>
    {actionLabel && onAction && (
      <div className="mt-4">
        <Button variant="secondary" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      </div>
    )}
  </div>
);

interface ErrorStateProps extends StateProps {
  onRetry?: () => void;
  errorCode?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Unable to load records',
  description = 'A communication failure or access restriction prevented loading this data.',
  onRetry,
  errorCode,
  className = '',
}) => (
  <div className={`flex flex-col items-center justify-center p-10 text-center rounded-md border border-rose-900/40 bg-rose-950/20 text-rose-200 ${className}`}>
    <div className="text-2xl text-rose-400 mb-2 select-none">⚠</div>
    <h4 className="text-sm font-semibold text-rose-100 tracking-tight">{title}</h4>
    <p className="mt-1 text-xs text-slate-300 max-w-sm">{description}</p>
    {errorCode && (
      <span className="mt-2 font-mono text-[10px] bg-rose-950/80 px-2 py-0.5 rounded border border-rose-800 text-rose-300">
        Code: {errorCode}
      </span>
    )}
    {onRetry && (
      <div className="mt-4">
        <Button variant="outline" size="sm" onClick={onRetry}>
          Retry Request
        </Button>
      </div>
    )}
  </div>
);
