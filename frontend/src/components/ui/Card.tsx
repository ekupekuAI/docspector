import React from 'react';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'muted' | 'danger' | 'warning' | 'success';
}

export const Card: React.FC<CardProps> = ({
  children,
  variant = 'default',
  className = '',
  ...props
}) => {
  const baseStyles = 'rounded-lg border p-5 sm:p-6 transition-all duration-150 shadow-sm';

  const variantStyles = {
    default: 'bg-slate-900/80 border-slate-800 text-slate-100 hover:border-slate-700/90 shadow-slate-950/40',
    muted: 'bg-slate-950 border-slate-850 text-slate-300',
    danger: 'bg-red-950/30 border-red-900/60 text-red-100',
    warning: 'bg-amber-950/30 border-amber-900/60 text-amber-100',
    success: 'bg-emerald-950/30 border-emerald-900/60 text-emerald-100',
  };

  return (
    <div className={`${baseStyles} ${variantStyles[variant]} ${className}`} {...props}>
      {children}
    </div>
  );
};

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className = '',
  ...props
}) => (
  <div className={`flex items-start justify-between pb-3.5 mb-4 border-b border-slate-800/80 gap-3 ${className}`} {...props}>
    {children}
  </div>
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  children,
  className = '',
  ...props
}) => (
  <h3 className={`text-base sm:text-lg font-bold tracking-tight text-slate-100 ${className}`} {...props}>
    {children}
  </h3>
);
