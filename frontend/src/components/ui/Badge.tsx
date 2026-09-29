import React from 'react';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'neutral' | 'info' | 'success' | 'warning' | 'danger';
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  className = '',
  ...props
}) => {
  const baseStyles = 'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium tracking-wide uppercase font-mono border select-none';

  const variantStyles = {
    neutral: 'bg-slate-800 text-slate-300 border-slate-700',
    info: 'bg-sky-950/60 text-sky-300 border-sky-800/80',
    success: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80',
    warning: 'bg-amber-950/60 text-amber-300 border-amber-800/80',
    danger: 'bg-rose-950/70 text-rose-300 border-rose-800/90 font-semibold',
  };

  return (
    <span className={`${baseStyles} ${variantStyles[variant]} ${className}`} {...props}>
      {children}
    </span>
  );
};
