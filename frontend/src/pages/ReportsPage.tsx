import React, { useEffect, useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { CaseRecord, CaseReportResponse } from '../types';
import { EmptyState } from '../components/ui/EmptyState';

export const ReportsPage: React.FC = () => {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [report, setReport] = useState<CaseReportResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLoadingReport, setIsLoadingReport] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId !== null) {
      fetchReport(selectedCaseId);
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

  const fetchReport = async (caseId: number) => {
    setIsLoadingReport(true);
    setError(null);
    try {
      const data = await api.getCaseReport(caseId);
      setReport(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to generate technical integrity report.');
      }
    } finally {
      setIsLoadingReport(false);
    }
  };

  const handleExport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Technical_Integrity_Report_${report.case?.case_number || 'CASE'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const firstDoc = report?.document_breakdown?.[0];
  const isVerified = report?.integrity?.custody_chain?.is_valid && (report?.integrity?.restricted_versions || 0) === 0;

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
            Technical Integrity
          </p>
          <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Technical Integrity Report</h1>
        </div>

        {cases.length > 0 && (
          <div className="flex items-center gap-2">
            <label className="text-xs font-sans text-slate-500 uppercase font-semibold">Select Case:</label>
            <select
              value={selectedCaseId ?? ''}
              onChange={(e) => setSelectedCaseId(Number(e.target.value))}
              className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-sans text-slate-700 outline-none focus:border-blue-500 font-medium"
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.title}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      {isLoading || isLoadingReport ? (
        <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
          Compiling technical integrity report from backend database...
        </div>
      ) : !report ? (
        <EmptyState title="Report unavailable" description="Report data could not be generated." />
      ) : (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="mb-4 flex items-center gap-2 text-slate-700">
            <FileText className="h-5 w-5 text-blue-600" />
            <span className="font-semibold text-lg">Case evidence summary</span>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Case ID</div>
              <div className="mt-1 font-medium text-slate-900 font-mono">{report.case?.case_number}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Document</div>
              <div className="mt-1 font-medium text-slate-900">{firstDoc?.title || 'Forensic Evidence Document'}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Version</div>
              <div className="mt-1 font-medium text-slate-900 font-mono">V{firstDoc?.latest_version_number || 1}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">SHA-256</div>
              <div className="mt-1 font-medium text-slate-900 font-mono text-xs truncate">
                {firstDoc?.latest_sha256 || 'RECORDED SHA-256 DIGEST'}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Verification result</div>
              <div className="mt-1 font-medium text-slate-900">
                {isVerified ? 'APPLICATION-LEVEL INTEGRITY VALID' : 'CRITICAL INTEGRITY FAILURE'}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Verification timestamp</div>
              <div className="mt-1 font-medium text-slate-900 font-mono text-xs">
                {new Date(report.generated_at).toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Custody events</div>
              <div className="mt-1 font-medium text-slate-900">{report.custody?.total_events || 0}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Integrity alerts</div>
              <div className="mt-1 font-medium text-slate-900">{report.integrity?.total_alerts || 0}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Current status</div>
              <div className="mt-1 font-medium text-slate-900">
                {report.integrity?.restricted_versions ? 'RESTRICTED' : 'VALID'}
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={handleExport}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 transition"
          >
            <Download className="h-4 w-4" /> Export Technical Integrity Report
          </button>
        </div>
      )}
    </div>
  );
};
