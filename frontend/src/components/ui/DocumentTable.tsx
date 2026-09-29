import React from 'react';
import { FileText, Eye, ShieldAlert } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { DocumentBreakdownItem } from '../../types';
import { StatusBadge } from '../status/StatusBadge';

interface DocumentTableProps {
  documents: DocumentBreakdownItem[];
}

export const DocumentTable: React.FC<DocumentTableProps> = ({ documents }) => {
  const navigate = useNavigate();

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-soft">
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm text-slate-700">
          <thead className="bg-slate-50">
            <tr>
              <th className="px-4 py-3 font-medium text-slate-600">Document</th>
              <th className="px-4 py-3 font-medium text-slate-600">Case</th>
              <th className="px-4 py-3 font-medium text-slate-600">Version</th>
              <th className="px-4 py-3 font-medium text-slate-600">Status</th>
              <th className="px-4 py-3 font-medium text-slate-600">Created</th>
              <th className="px-4 py-3 font-medium text-slate-600">Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.map((document) => {
              const state = document.latest_state || document.current_state || 'STORED';
              return (
                <tr key={document.document_id} className="border-t border-slate-200 hover:bg-slate-50 transition-colors duration-150 ease-in-out">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-100 text-slate-600 shrink-0">
                        <FileText className="h-4 w-4" />
                      </div>
                      <div>
                        <Link
                          to={`/documents/${document.document_id}`}
                          className="font-medium text-slate-900 hover:text-blue-600"
                        >
                          {document.title}
                        </Link>
                        <div className="text-xs font-mono text-slate-500">{document.document_number}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">DOC-{document.document_id}</td>
                  <td className="px-4 py-3 font-mono text-xs">
                    V{document.latest_version_number || document.version_count || 1}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={state} />
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {new Date(document.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/documents/${document.document_id}`}
                        className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-100 transition"
                        title="View Document Details"
                      >
                        <Eye className="h-4 w-4" />
                      </Link>
                      <button
                        type="button"
                        onClick={() => navigate(`/documents/${document.document_id}/versions/${document.latest_version_number || 1}`)}
                        className="rounded-lg border border-red-200 bg-red-50 p-2 text-red-600 hover:bg-red-100 transition"
                        title="Inspect Cryptographic Version"
                      >
                        <ShieldAlert className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
