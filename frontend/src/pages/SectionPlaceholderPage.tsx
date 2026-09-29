import React from 'react';
import { EmptyState } from '../components/ui/States';
import { NavRoute } from '../types';

interface SectionPlaceholderPageProps {
  route: NavRoute;
  title: string;
  description: string;
  backendMilestone: string;
  onNavigateHome: () => void;
}

export const SectionPlaceholderPage: React.FC<SectionPlaceholderPageProps> = ({
  route,
  title,
  description,
  backendMilestone,
  onNavigateHome,
}) => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <span className="text-[10px] font-mono tracking-widest uppercase text-slate-400">
            Navigation Shell / {route.toUpperCase()}
          </span>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">{title}</h1>
          <p className="text-xs text-slate-400 mt-1">{description}</p>
        </div>

        <div className="flex items-center gap-2">
          <span className="font-mono text-xs px-2.5 py-1 bg-slate-900 border border-slate-800 text-slate-400 rounded">
            Backend APIs Ready ({backendMilestone})
          </span>
        </div>
      </div>

      <EmptyState
        title={`${title} View Ready for Component Implementation`}
        description={`The backend API contracts and authorization rules (${backendMilestone}) are active. Presentation components for this view will be plugged into this shell in upcoming milestones.`}
        actionLabel="Return to Dashboard"
        onAction={onNavigateHome}
      />
    </div>
  );
};
