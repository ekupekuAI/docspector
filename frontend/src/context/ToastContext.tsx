import React, { createContext, useContext, useState, useCallback } from 'react';

export type ToastType = 'success' | 'info' | 'warning' | 'error';

export interface ToastItem {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
}

interface ToastContextValue {
  toasts: ToastItem[];
  showToast: (toast: Omit<ToastItem, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    ({ type, title, message, duration = 4000 }: Omit<ToastItem, 'id'>) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const newToast: ToastItem = { id, type, title, message, duration };

      setToasts((prev) => [...prev, newToast]);

      if (duration > 0) {
        setTimeout(() => {
          removeToast(id);
        }, duration);
      }
    },
    [removeToast]
  );

  return (
    <ToastContext.Provider value={{ toasts, showToast, removeToast }}>
      {children}
      {/* Toast Render Container */}
      <div
        className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-md w-full pointer-events-none px-4"
        aria-live="polite"
        role="region"
        aria-label="Notification Toasts"
      >
        {toasts.map((toast) => {
          const typeStyles = {
            success: 'bg-slate-900 border-emerald-600/90 text-emerald-200 shadow-emerald-950/40',
            info: 'bg-slate-900 border-sky-600/90 text-sky-200 shadow-sky-950/40',
            warning: 'bg-slate-900 border-amber-600/90 text-amber-200 shadow-amber-950/40',
            error: 'bg-slate-900 border-red-600/90 text-red-200 shadow-red-950/40',
          }[toast.type];

          const icon = {
            success: '✓',
            info: 'ℹ',
            warning: '⚠',
            error: '✕',
          }[toast.type];

          return (
            <div
              key={toast.id}
              className={`pointer-events-auto p-4 rounded-lg border-2 shadow-xl flex items-start gap-3 animate-toast ${typeStyles}`}
            >
              <span className="text-base font-bold select-none shrink-0" aria-hidden="true">
                {icon}
              </span>
              <div className="flex-1 space-y-0.5 text-xs">
                <div className="font-bold text-slate-100 text-sm tracking-tight">{toast.title}</div>
                {toast.message && (
                  <div className="text-slate-300 text-xs leading-relaxed">{toast.message}</div>
                )}
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="text-slate-400 hover:text-slate-200 text-xs font-mono p-1 rounded hover:bg-slate-800 transition shrink-0"
                aria-label="Close notification"
              >
                ✕
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextValue => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
