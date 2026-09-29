import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => {
  const baseStyles =
    'inline-flex items-center justify-center font-semibold transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:opacity-50 disabled:cursor-not-allowed select-none active:scale-[0.98] font-sans';

  const sizeStyles = {
    sm: 'text-sm px-3.5 py-2 rounded-xl gap-2',
    md: 'text-base px-4.5 py-2.5 rounded-xl gap-2.5',
    lg: 'text-base sm:text-lg px-6 py-3 rounded-xl gap-3',
  };

  const variantStyles = {
    primary:
      'bg-slate-100 text-slate-950 hover:bg-white active:bg-slate-200 border border-slate-300 shadow-sm font-semibold',
    secondary:
      'bg-slate-800 text-slate-100 hover:bg-slate-700 active:bg-slate-800 border border-slate-700 shadow-sm',
    danger:
      'bg-red-950 text-red-100 hover:bg-red-900 active:bg-red-950 border border-red-700 font-semibold shadow-sm',
    ghost:
      'text-slate-300 hover:bg-slate-800 hover:text-white border border-transparent',
    outline:
      'border border-slate-700 bg-slate-950/60 text-slate-200 hover:bg-slate-800 hover:border-slate-600 hover:text-white',
  };

  return (
    <button
      className={`${baseStyles} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className="w-4.5 h-4.5 border-2 border-current border-t-transparent rounded-full animate-spin mr-1.5" />
      ) : icon ? (
        <span className="inline-flex shrink-0">{icon}</span>
      ) : null}
      {children}
    </button>
  );
};
