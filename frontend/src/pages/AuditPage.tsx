import React, { useEffect, useMemo, useState } from 'react';
import { Filter } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { CaseRecord, CaseAuditResponse } from '../types';
import { AuditTable } from '../components/ui/AuditTable';
import { EmptyState } from '../components/ui/EmptyState';

export const AuditPage: React.FC = () => {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [auditData, setAuditData] = useState<CaseAuditResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLoadingAudit, setIsLoadingAudit] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>('ALL');

  useEffect(() => {
    fetchCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId !== null) {
      fetchAudit(selectedCaseId);
    }
  }, [selectedCaseId]);

  const fetchCases = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const caseList = await api.getCases();
      setCases(caseList);
      if (caseList.length > 0) {
        setSelectedCaseId(caseList[0].id);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch assigned cases.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const fetchAudit = async (caseId: number) => {
    setIsLoadingAudit(true);
    setError(null);
    try {
      const data = await api.getCaseAudit(caseId);
      setAuditData(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch custody audit ledger.');
      }
    } finally {
      setIsLoadingAudit(false);
    }
  };

  const filteredEvents = useMemo(() => {
    if (!auditData?.events) return [];
    return auditData.events.filter((evt) => {
      const matchesAction = actionFilter === 'ALL' || evt.event_type === actionFilter;
      return matchesAction;
    });
  }, [auditData, actionFilter]);

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
          Audit Workspace
        </p>
        <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Read-Only Audit Trail</h1>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Filter Control Bar */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="grid gap-3 md:grid-cols-3">
          {cases.length > 0 && (
            <select
              value={selectedCaseId ?? ''}
              onChange={(e) => setSelectedCaseId(Number(e.target.value))}
              className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-700 outline-none focus:border-blue-500"
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.title}
                </option>
              ))}
            </select>
          )}

          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-700 outline-none focus:border-blue-500"
          >
            <option value="ALL font-mono">All Actions</option>
            <option value="DOCUMENT_INGESTED">DOCUMENT_INGESTED</option>
            <option value="VERSION_CREATED">VERSION_CREATED</option>
            <option value="TRANSFER_REQUESTED">TRANSFER_REQUESTED</option>
            <option value="TRANSFER_APPROVED">TRANSFER_APPROVED</option>
            <option value="INTEGRITY_ALERT">INTEGRITY_ALERT</option>
          </select>

          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-100 transition"
          >
            <Filter className="h-4 w-4" /> Filters
          </button>
        </div>
      </div>

      {/* Audit Table */}
      {isLoading || isLoadingAudit ? (
        <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
          Computing hash-chained audit verification...
        </div>
      ) : filteredEvents.length === 0 ? (
        <EmptyState
          title="No audit events"
          description="No custody events match the selected case or action filters."
        />
      ) : (
        <AuditTable
          events={filteredEvents}
          caseNumber={auditData?.case_number || 'CASE-001'}
        />
      )}
    </div>
  );
};
