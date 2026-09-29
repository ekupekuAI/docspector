import React from 'react';
import { CustodyEventItem } from '../../types';
import { StatusBadge } from '../status/StatusBadge';

interface AuditTableProps {
  events: CustodyEventItem[];
  caseNumber?: string;
}

export const AuditTable: React.FC<AuditTableProps> = ({ events, caseNumber = 'CASE-001' }) => {
  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-soft">
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm text-slate-700 font-sans">
          <thead className="bg-slate-50">
            <tr>
              <th className="px-4 py-3 font-medium text-slate-600">Event ID</th>
              <th className="px-4 py-3 font-medium text-slate-600">Case</th>
              <th className="px-4 py-3 font-medium text-slate-600">Document / Version</th>
              <th className="px-4 py-3 font-medium text-slate-600">Actor ID</th>
              <th className="px-4 py-3 font-medium text-slate-600">Action</th>
              <th className="px-4 py-3 font-medium text-slate-600">Timestamp</th>
              <th className="px-4 py-3 font-medium text-slate-600">Status</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt) => (
              <tr key={evt.id} className="border-t border-slate-200 hover:bg-slate-50 transition-colors duration-150 ease-in-out">
                <td className="px-4 py-3 font-mono font-bold text-slate-900">
                  #{String(evt.sequence_number ?? evt.id).padStart(3, '0')}
                </td>
                <td className="px-4 py-3 font-mono text-slate-700">{caseNumber}</td>
                <td className="px-4 py-3 font-mono text-xs">
                  {evt.document_version_id ? `V#${evt.document_version_id}` : 'General Case Event'}
                </td>
                <td className="px-4 py-3 font-medium text-slate-800">User #{evt.actor_user_id}</td>
                <td className="px-4 py-3">
                  <span className="font-semibold text-slate-800 text-xs font-mono uppercase bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                    {evt.event_type}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-slate-500 font-mono">
                  {new Date(evt.event_time || evt.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status="VALID" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
