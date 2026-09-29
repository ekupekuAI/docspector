import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { FileText, ShieldAlert, ShieldCheck, UserRound, ArrowRight, Plus } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { CaseRecord, CustodyEventItem, IntegrityAlertSummary, DocumentBreakdownItem } from '../types';
import { RoleSwitcher } from '../components/ui/RoleSwitcher';
import { StatusBadge } from '../components/status/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { CustodyTimeline } from '../components/transfers/CustodyTimeline';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

export const CaseDetailPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const { user } = useAuth();
  const { showToast } = useToast();

  const [caseRecord, setCaseRecord] = useState<CaseRecord | null>(null);
  const [alerts, setAlerts] = useState<IntegrityAlertSummary[]>([]);
  const [custodyEvents, setCustodyEvents] = useState<CustodyEventItem[]>([]);
  const [documents, setDocuments] = useState<DocumentBreakdownItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Upload modal state
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadTitle, setUploadTitle] = useState<string>('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [showUploadModal, setShowUploadModal] = useState<boolean>(false);

  useEffect(() => {
    if (caseId) {
      fetchCaseDetails(Number(caseId));
    }
  }, [caseId]);

  const fetchCaseDetails = async (id: number) => {
    setIsLoading(true);
    setError(null);
    try {
      const caseData = await api.getCase(id);
      setCaseRecord(caseData);

      const [alertList, auditData, reportData] = await Promise.all([
        api.getCaseAlerts(id).catch(() => []),
        api.getCaseAudit(id).catch(() => null),
        api.getCaseReport(id).catch(() => null),
      ]);

      setAlerts(alertList);
      if (auditData?.events) setCustodyEvents(auditData.events);
      if (reportData?.document_breakdown) setDocuments(reportData.document_breakdown);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch case details.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseId || !uploadFile || !uploadTitle.trim()) return;

    setIsUploading(true);
    try {
      await api.uploadDocument(Number(caseId), uploadFile, uploadTitle.trim());
      showToast({
        type: 'success',
        title: 'Evidence Ingested',
        message: `Successfully uploaded ${uploadFile.name} to Case #${caseId}`,
      });
      setShowUploadModal(false);
      setUploadTitle('');
      setUploadFile(null);
      fetchCaseDetails(Number(caseId));
    } catch (err) {
      if (err instanceof ApiError) {
        showToast({
          type: 'error',
          title: 'Upload Failed',
          message: err.message,
        });
      } else {
        showToast({
          type: 'error',
          title: 'Upload Error',
          message: 'Network error during upload.',
        });
      }
    } finally {
      setIsUploading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
        Loading case details...
      </div>
    );
  }

  if (error || !caseRecord) {
    return (
      <EmptyState
        title="Case Not Found"
        description={error || "The requested case record could not be loaded."}
      />
    );
  }

  const isOfficer = user?.role === 'IO' || user?.role === 'SO';

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* Header Banner */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
            Case details
          </p>
          <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">{caseRecord.title}</h1>
        </div>
        <RoleSwitcher />
      </div>

      {/* Primary Case Record Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft card-interactive">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 font-mono">
              {caseRecord.case_number}
            </div>
            <div className="mt-1.5 text-xl font-bold text-slate-900 font-sans">{caseRecord.title}</div>
          </div>
          <StatusBadge status={caseRecord.status} />
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">Case ID</div>
            <div className="mt-1 font-medium text-slate-800 font-mono">#{caseRecord.id}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Status</div>
            <div className="mt-1 font-medium text-slate-800">{caseRecord.status}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Assigned Officer</div>
            <div className="mt-1 font-medium text-slate-800">{user?.display_name || 'Investigator'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Created Date</div>
            <div className="mt-1 font-medium text-slate-800">
              {new Date(caseRecord.created_at).toLocaleString()}
            </div>
          </div>
        </div>

        {caseRecord.description && (
          <div className="mt-4 p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs text-slate-600">
            {caseRecord.description}
          </div>
        )}
      </div>

      {/* Two Column Section */}
      <div className="grid gap-6 xl:grid-cols-2">
        {/* Left Column */}
        <div className="space-y-6">
          {/* Documents Card */}
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-blue-600" />
                <h3 className="text-xl font-bold text-slate-900">Documents</h3>
              </div>
              {isOfficer && (
                <button
                  onClick={() => setShowUploadModal(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 transition"
                >
                  <Plus className="h-3.5 w-3.5" /> Upload Evidence
                </button>
              )}
            </div>

            {documents.length === 0 ? (
              <EmptyState title="No documents in this case" />
            ) : (
              <div className="space-y-3">
                {documents.map((doc) => (
                  <div
                    key={doc.document_id}
                    className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3 hover:bg-slate-100/80 transition"
                  >
                    <div>
                      <Link
                        to={`/documents/${doc.document_id}`}
                        className="font-medium text-slate-900 hover:text-blue-600 text-sm"
                      >
                        {doc.title}
                      </Link>
                      <div className="text-xs text-slate-500 font-mono">
                        {doc.document_number} • Latest V{doc.latest_version_number || 1}
                      </div>
                    </div>
                    <StatusBadge status={doc.latest_state || 'STORED'} />
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Integrity Alerts Card */}
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
            <div className="mb-4 flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-600" />
              <h3 className="text-xl font-bold text-slate-900">Integrity alerts</h3>
            </div>
            {alerts.length === 0 ? (
              <EmptyState title="No integrity alerts" />
            ) : (
              <div className="space-y-3">
                {alerts.map((alert) => (
                  <div key={alert.id} className="rounded-xl border border-red-200 bg-red-50 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium text-red-900 text-sm">{alert.alert_type}</div>
                      <StatusBadge status={alert.status} />
                    </div>
                    <div className="mt-1 text-xs text-red-700 font-sans">{alert.message}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Transfer Activity Card */}
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
            <div className="mb-4 flex items-center gap-2">
              <UserRound className="h-5 w-5 text-blue-600" />
              <h3 className="text-xl font-bold text-slate-900">Transfer activity</h3>
            </div>
            <div className="space-y-3">
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">
                <div className="font-semibold text-slate-800 text-sm">Transfer Queue Summary</div>
                <p className="mt-1 text-slate-500">
                  Transfers require Supervisory Officer authorization to update custody boundaries.
                </p>
                <div className="mt-3">
                  <Link
                    to="/transfers"
                    className="inline-flex items-center gap-1 font-semibold text-blue-600 hover:underline"
                  >
                    Open Transfer Center <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
              </div>
            </div>
          </div>

          {/* Verification Results Card */}
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-600" />
                <h3 className="text-xl font-bold text-slate-900">Verification & Report</h3>
              </div>
              <Link
                to="/reports"
                className="text-xs font-semibold text-blue-600 hover:underline"
              >
                View Full Report →
              </Link>
            </div>
            <div className="p-4 rounded-xl border border-emerald-200 bg-emerald-50 text-emerald-800 text-xs space-y-1 font-sans">
              <div className="font-semibold text-emerald-900">Application-Level Verification Available</div>
              <p>Recompute physical SHA-256 byte digests and audit custody ledger continuity.</p>
              <div className="pt-2">
                <Link
                  to="/verify"
                  className="inline-flex items-center gap-1 font-bold text-emerald-700 hover:underline"
                >
                  Run Verification Console →
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Custody Timeline */}
      <CustodyTimeline events={custodyEvents} />

      {/* Upload Evidence Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in">
          <div className="bg-white rounded-2xl border border-slate-200 p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-lg font-bold text-slate-900">Upload Evidence Document</h3>
              <button
                onClick={() => setShowUploadModal(false)}
                className="text-slate-400 hover:text-slate-600 text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-700 font-semibold mb-1 uppercase tracking-wider">
                  Document Title
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Digital Forensic Disk Image"
                  value={uploadTitle}
                  onChange={(e) => setUploadTitle(e.target.value)}
                  className="w-full rounded-xl border border-slate-300 p-2.5 text-xs text-slate-900 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-700 font-semibold mb-1 uppercase tracking-wider">
                  Select File
                </label>
                <input
                  type="file"
                  required
                  onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                  className="w-full text-xs text-slate-700 file:mr-3 file:py-2 file:px-3 file:rounded-xl file:border-0 file:bg-blue-50 file:text-blue-700 file:font-semibold hover:file:bg-blue-100 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 rounded-xl text-slate-600 hover:bg-slate-100 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isUploading || !uploadFile || !uploadTitle.trim()}
                  className="px-4 py-2 rounded-xl bg-blue-600 text-white font-semibold hover:bg-blue-700 disabled:opacity-50"
                >
                  {isUploading ? 'Uploading...' : 'Ingest Evidence'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
