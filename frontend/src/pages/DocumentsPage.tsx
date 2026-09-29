import React, { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { DocumentBreakdownItem } from '../types';
import { DocumentTable } from '../components/ui/DocumentTable';
import { EmptyState } from '../components/ui/EmptyState';

export const DocumentsPage: React.FC = () => {
  const [documents, setDocuments] = useState<DocumentBreakdownItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDocumentsData();
  }, []);

  const fetchDocumentsData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const caseList = await api.getCases();
      const allDocs: DocumentBreakdownItem[] = [];

      for (const c of caseList) {
        try {
          const report = await api.getCaseReport(c.id);
          if (report.document_breakdown) {
            allDocs.push(...report.document_breakdown);
          }
        } catch {
          // ignore report fetch errors for single cases
        }
      }
      setDocuments(allDocs);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch document registry.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const filtered = documents.filter(
    (doc) =>
      doc.title.toLowerCase().includes(search.toLowerCase()) ||
      doc.document_number.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* Header & Controls */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
            Document registry
          </p>
          <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Evidence Documents</h1>
        </div>

        <div className="flex flex-col gap-3 md:flex-row">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search documents"
              className="w-full rounded-xl border border-slate-200 bg-white pl-10 pr-4 py-2.5 text-sm text-slate-700 md:w-72 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            />
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Document Table */}
      {isLoading ? (
        <div className="p-12 text-center text-slate-500 text-sm animate-pulse">
          Loading evidence documents...
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          title="No documents"
          description="No evidence files match your current search criteria."
        />
      ) : (
        <DocumentTable documents={filtered} />
      )}
    </div>
  );
};
