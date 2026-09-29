import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Lock, ShieldAlert } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { DocumentCustodyResponse } from '../types';
import { StatusBadge } from '../components/status/StatusBadge';
import { HashDisplay } from '../components/ui/HashDisplay';
import { EmptyState } from '../components/ui/EmptyState';
import { AccessDenied } from '../components/ui/AccessDenied';

export const DocumentDetailPage: React.FC = () => {
  const { documentId } = useParams<{ documentId: string }>();
  const [custodyData, setCustodyData] = useState<DocumentCustodyResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (documentId) {
      fetchCustody();
    }
  }, [documentId]);

  const fetchCustody = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getDocumentCustody(Number(documentId));
      setCustodyData(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch document detail.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
        Loading document detail...
      </div>
    );
  }

  if (error || !custodyData) {
    return (
      <EmptyState
        title="Document not found"
        description={error || "The requested evidence document could not be located."}
      />
    );
  }

  const latestEvent = custodyData.events[custodyData.events.length - 1];
  const isChainValid = custodyData.chain_integrity?.is_valid ?? true;
  const state = isChainValid ? 'STORED' : 'RESTRICTED';

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* Top Document Header Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
              Document Details
            </p>
            <h1 className="mt-1 text-3xl font-bold text-slate-900 font-mono">
              {custodyData.document_number}
            </h1>
          </div>
          <StatusBadge status={state} />
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">Document ID</div>
            <div className="mt-1 font-medium text-slate-800 font-mono">DOC-{custodyData.document_id}</div>
          </div>
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">Case ID</div>
            <div className="mt-1 font-medium text-slate-800 font-mono">CASE #{custodyData.case_id}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Total Custody Events</div>
            <div className="mt-1 font-medium text-slate-800">{custodyData.events.length}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Chain Status</div>
            <div className="mt-1 font-medium text-slate-800">{custodyData.chain_integrity?.status || 'VALID'}</div>
          </div>
        </div>

        {/* Versioned Evidence Access Container */}
        <div className="mt-6 rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="mb-3 flex items-center gap-2 text-slate-700">
            <Lock className="h-5 w-5 text-slate-500" />
            <span className="font-semibold text-sm">Versioned evidence access</span>
          </div>

          {!isChainValid ? (
            <AccessDenied message="Access restricted: custody chain hash integrity check failed for this document." />
          ) : (
            <div className="grid gap-4 xl:grid-cols-2">
              <HashDisplay
                hash={latestEvent?.event_hash || 'SHA-256 Digest Record'}
                label="LATEST EVENT SHA-256 DIGEST"
              />
              <div className="rounded-xl border border-slate-200 bg-white p-3">
                <div className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Version history
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Link
                    to={`/documents/${custodyData.document_id}/versions/1`}
                    className="rounded-full border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100 transition font-mono"
                  >
                    Version V1
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Integrity Summary Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="mb-4 flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-amber-600" />
          <h3 className="text-xl font-bold text-slate-900">Integrity summary</h3>
        </div>
        <div className="space-y-2 text-sm text-slate-600 font-mono text-xs">
          <div>Current status: <span className="font-semibold text-slate-900">{state}</span></div>
          <div>Custody Events Count: <span className="font-semibold text-slate-900">{custodyData.events.length}</span></div>
          <div>Last Event SHA-256: <span className="font-semibold text-slate-800">{latestEvent?.event_hash}</span></div>
        </div>
      </div>
    </div>
  );
};
