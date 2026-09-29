import React from 'react';

export interface AlertProps {
  variant?: 'info' | 'warning' | 'error' | 'success' | 'critical';
  title?: string;
  description?: string | React.ReactNode;
  children?: React.ReactNode;
  onDismiss?: () => void;
  className?: string;
}

export const Alert: React.FC<AlertProps> = ({
  variant = 'info',
  title,
  description,
  children,
  onDismiss,
  className = '',
}) => {
  const variantConfig = {
    info: {
      container: 'bg-slate-900/90 border-sky-800/80 text-sky-200',
      icon: 'ℹ',
      iconColor: 'text-sky-400',
      titleColor: 'text-sky-200',
    },
    warning: {
      container: 'bg-amber-950/40 border-amber-700/80 text-amber-200',
      icon: '⚠',
      iconColor: 'text-amber-400',
      titleColor: 'text-amber-100',
    },
    error: {
      container: 'bg-rose-950/40 border-rose-700/80 text-rose-200',
      icon: '✕',
      iconColor: 'text-rose-400',
      titleColor: 'text-rose-100',
    },
    success: {
      container: 'bg-emerald-950/40 border-emerald-700/80 text-emerald-200',
      icon: '✓',
      iconColor: 'text-emerald-400',
      titleColor: 'text-emerald-100',
    },
    critical: {
      container: 'bg-red-950/90 border-red-600 text-red-100 shadow-lg shadow-red-950/50 animate-alert-attention',
      icon: '🔴',
      iconColor: 'text-red-400',
      titleColor: 'text-white font-bold tracking-wide',
    },
  };

  const config = variantConfig[variant];

  return (
    <div
      role="alert"
      className={`rounded-md border p-4 flex gap-3.5 transition-all duration-200 ${config.container} ${className}`}
    >
      <div className={`text-base font-bold select-none shrink-0 ${config.iconColor}`} aria-hidden="true">
        {config.icon}
      </div>
      <div className="flex-1 space-y-1 text-sm leading-relaxed">
        {title && <h4 className={`text-sm font-semibold tracking-tight ${config.titleColor}`}>{title}</h4>}
        {description && <div className="text-slate-300 text-xs sm:text-sm">{description}</div>}
        {children}
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-slate-400 hover:text-slate-200 text-sm font-mono h-6 w-6 flex items-center justify-center rounded hover:bg-white/10 shrink-0"
          aria-label="Dismiss alert"
        >
          ✕
        </button>
      )}
    </div>
  );
};
