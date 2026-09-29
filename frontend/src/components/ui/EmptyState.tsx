import React from 'react';

interface EmptyStateProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ title, description, action }) => {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center shadow-soft">
      <h3 className="text-lg font-semibold text-slate-800">{title}</h3>
      {description ? <p className="mt-2 text-sm text-slate-500 font-sans">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
};
