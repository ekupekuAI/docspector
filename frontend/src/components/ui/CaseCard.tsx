import React from 'react';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { CaseRecord } from '../../types';
import { StatusBadge } from '../status/StatusBadge';

interface CaseCardProps {
  caseItem: CaseRecord & { secureFileCount?: number; priority?: string; assignedOfficer?: string };
}

export const CaseCard: React.FC<CaseCardProps> = ({ caseItem }) => {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-soft card-interactive">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-bold uppercase tracking-wider text-slate-500 font-mono">
            {caseItem.case_number}
          </p>
          <h3 className="mt-2 text-xl sm:text-2xl font-bold text-slate-900 font-sans">{caseItem.title}</h3>
        </div>
        <StatusBadge status={caseItem.status} />
      </div>

      <div className="mt-5 grid gap-4 text-base text-slate-600 sm:grid-cols-2">
        <div>
          <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Assigned Officer</div>
          <div className="mt-1 font-medium text-slate-800 font-sans">
            {caseItem.assignedOfficer || 'Investigating Officer'}
          </div>
        </div>
        <div>
          <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Created Date</div>
          <div className="mt-1 font-medium text-slate-800 font-sans">
            {new Date(caseItem.created_at).toLocaleDateString()}
          </div>
        </div>
      </div>

      <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-base text-slate-600 font-sans">
        <span>{caseItem.secureFileCount ?? 1} evidence records</span>
        <Link
          to={`/cases/${caseItem.id}`}
          className="inline-flex items-center gap-2 font-semibold text-blue-600 hover:text-blue-700 transition-colors duration-150"
        >
          Open Case <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </div>
  );
};
