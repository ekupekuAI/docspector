import React, { useEffect, useState } from 'react';
import { AlertTriangle, ShieldCheck, ShieldX, Sparkles } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { CaseRecord, IntegrityAlertSummary, VerificationResponse, DemoTamperResponse } from '../types';
import { StatusBadge } from '../components/status/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { useToast } from '../context/ToastContext';

export const IntegrityPage: React.FC = () => {
  const { showToast } = useToast();

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [alerts, setAlerts] = useState<IntegrityAlertSummary[]>([]);
  const [verificationResult, setVerificationResult] = useState<VerificationResponse | null>(null);
  const [tamperSuccess, setTamperSuccess] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isTampering, setIsTampering] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Resolution Modal
  const [resolvingAlert, setResolvingAlert] = useState<IntegrityAlertSummary | null>(null);
  const [resolutionReason, setResolutionReason] = useState<string>('');
  const [isResolving, setIsResolving] = useState<boolean>(false);
  const [resolutionError, setResolutionError] = useState<string | null>(null);

  useEffect(() => {
    fetchCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      fetchCaseAlerts(selectedCaseId);
    }
  }, [selectedCaseId]);

  const fetchCases = async () => {
    try {
      const caseList = await api.getCases();
      setCases(caseList);
      if (caseList.length > 0) {
        setSelectedCaseId(caseList[0].id);
      }
    } catch {
      setError('Failed to fetch assigned cases.');
    }
  };

  const fetchCaseAlerts = async (caseId: number) => {
    try {
      const data = await api.getCaseAlerts(caseId);
      setAlerts(data);
    } catch {
      // ignore
    }
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    setVerificationResult(null);
    setError(null);
    try {
      const resp = await api.verifyDocumentVersion(1, 1);
      setVerificationResult(resp);
      if (resp.overall_status === 'VALID') {
        showToast({ type: 'success', title: 'Integrity Verified', message: 'Document version V1 is cryptographically valid.' });
      } else {
        showToast({ type: 'error', title: 'CRITICAL: Integrity Failure', message: 'File hash mismatch detected! Version restricted.' });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Verification check failed.');
      }
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamper = async () => {
    setIsTampering(true);
    setError(null);
    setTamperSuccess(null);
    try {
      const resp: DemoTamperResponse = await api.simulateTamper(1, 1);
      setTamperSuccess(`Synthetic disk bytes corrupted for DOC-0001 (V${resp.version_number}). Persisted DB hash preserved. Click "Verify Integrity" to execute automated detection.`);
      showToast({ type: 'warning', title: 'Synthetic Corruption Applied (DEMO MODE)', message: 'Physical disk bytes corrupted on disk.' });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Tamper simulation failed.');
      }
    } finally {
      setIsTampering(false);
    }
  };

  const handleResolveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolvingAlert || !resolutionReason.trim()) return;

    setIsResolving(true);
    setResolutionError(null);
    try {
      await api.resolveAlert(resolvingAlert.id, resolutionReason.trim());
      showToast({ type: 'success', title: 'Alert Resolved', message: `Alert #${resolvingAlert.id} resolved following backend re-verification.` });
      setResolvingAlert(null);
      if (selectedCaseId) fetchCaseAlerts(selectedCaseId);
    } catch (err) {
      if (err instanceof ApiError) {
        setResolutionError(err.message);
      } else {
        setResolutionError('Resolution failed backend re-verification.');
      }
    } finally {
      setIsResolving(false);
    }
  };

  const openAlerts = alerts.filter((a) => a.status === 'OPEN');
  const resolvedAlerts = alerts.filter((a) => a.status === 'RESOLVED');

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
            Integrity Center
          </p>
          <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Integrity Overview</h1>
        </div>

        {cases.length > 0 && (
          <div className="flex items-center gap-2">
            <label className="text-xs font-sans text-slate-500 uppercase font-semibold">Case Scope:</label>
            <select
              value={selectedCaseId ?? ''}
              onChange={(e) => setSelectedCaseId(Number(e.target.value))}
              className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-mono text-slate-700 outline-none focus:border-blue-500"
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

      {/* Top 4 Metrics Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold">
            <ShieldCheck className="h-5 w-5 text-emerald-600" /> Valid
          </div>
          <div className="mt-4 text-3xl font-bold text-slate-900 font-mono">
            {openAlerts.length === 0 ? '1' : '0'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold">
            <ShieldX className="h-5 w-5 text-red-600" /> Restricted
          </div>
          <div className="mt-4 text-3xl font-bold text-slate-900 font-mono">
            {openAlerts.length > 0 ? '1' : '0'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold">
            <AlertTriangle className="h-5 w-5 text-amber-600" /> Reviewed
          </div>
          <div className="mt-4 text-3xl font-bold text-slate-900 font-mono">
            {resolvedAlerts.length}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold">
            <Sparkles className="h-5 w-5 text-blue-600" /> Alerts
          </div>
          <div className="mt-4 text-3xl font-bold text-slate-900 font-mono">
            {alerts.length}
          </div>
        </div>
      </div>

      {/* Action Control Panel Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={handleVerify}
            disabled={isVerifying}
            className="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 transition disabled:opacity-50"
          >
            {isVerifying ? 'Computing SHA-256...' : 'Verify Integrity'}
          </button>
          <button
            type="button"
            onClick={handleTamper}
            disabled={isTampering}
            className="rounded-xl bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-700 transition disabled:opacity-50"
            title="Controlled synthetic tamper (DEMO MODE)"
          >
            {isTampering ? 'Corrupting Disk Bytes...' : 'SIMULATE DEMO TAMPER ⚠'}
          </button>
        </div>

        {tamperSuccess && (
          <div className="mt-5 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-amber-900 text-xs font-sans">
            <strong className="block text-amber-800 font-bold mb-1 uppercase tracking-wider">
              DEMO TAMPER EXECUTED
            </strong>
            {tamperSuccess}
          </div>
        )}

        {verificationResult && (
          <div
            className={`mt-5 rounded-2xl border p-5 shadow-sm font-sans ${
              verificationResult.overall_status === 'VALID'
                ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                : 'border-red-200 bg-red-50 text-red-900'
            }`}
          >
            <div className="text-xs font-semibold uppercase tracking-wide">
              INTEGRITY VERIFICATION RESULT: {verificationResult.overall_status}
            </div>
            <div className="mt-3 text-sm font-bold">
              File Digest: {verificationResult.file_integrity.is_valid ? 'VALID' : 'HASH MISMATCH DETECTED'}
            </div>
            <div className="mt-1 text-xs font-mono">
              Stored SHA-256: {verificationResult.file_integrity.stored_hash}
            </div>
            {verificationResult.file_integrity.computed_hash && (
              <div className="mt-1 text-xs font-mono text-red-700">
                Computed SHA-256: {verificationResult.file_integrity.computed_hash}
              </div>
            )}
            <div className="mt-2 text-xs">
              State: <strong>{verificationResult.version_state}</strong>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-mono">
            {error}
          </div>
        )}
      </div>

      {/* Two Column Grid */}
      <div className="grid gap-6 xl:grid-cols-2">
        {/* Open Alerts List */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <h3 className="text-xl font-bold text-slate-900 mb-4">Open alerts</h3>
          {alerts.length === 0 ? (
            <EmptyState title="No integrity alerts" />
          ) : (
            <div className="space-y-3">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`rounded-xl border p-4 transition ${
                    alert.status === 'OPEN'
                      ? 'border-red-200 bg-red-50 text-red-900'
                      : 'border-slate-200 bg-slate-50 text-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-semibold text-sm">{alert.alert_type}</div>
                    <StatusBadge status={alert.status} />
                  </div>
                  <div className="mt-2 text-xs text-slate-700 font-sans">{alert.message}</div>
                  {alert.status === 'OPEN' && (
                    <div className="mt-3 pt-2 border-t border-red-200 flex justify-end">
                      <button
                        onClick={() => {
                          setResolvingAlert(alert);
                          setResolutionReason('');
                          setResolutionError(null);
                        }}
                        className="px-3 py-1 bg-red-600 text-white rounded-lg text-xs font-semibold hover:bg-red-700 transition"
                      >
                        Resolve Alert 🛡
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Restricted Versions List */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <h3 className="text-xl font-bold text-slate-900 mb-4">Restricted versions</h3>
          {openAlerts.length === 0 ? (
            <EmptyState title="No restricted versions" />
          ) : (
            <div className="space-y-3">
              {openAlerts.map((alert) => (
                <div key={alert.id} className="rounded-xl border border-red-200 bg-red-50 p-4">
                  <div className="font-bold text-red-900 text-sm">Evidence Document Version</div>
                  <div className="mt-1 text-xs text-red-700 font-mono">
                    Doc Version ID: #{alert.document_version_id || 1} • State: RESTRICTED
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Resolution Modal */}
      {resolvingAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in">
          <div className="bg-white rounded-2xl border border-slate-200 p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-lg font-bold text-slate-900">
                Resolve Integrity Alert #{resolvingAlert.id}
              </h3>
              <button onClick={() => setResolvingAlert(null)} className="text-slate-400 hover:text-slate-600 text-lg font-bold">
                ✕
              </button>
            </div>

            <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-800 leading-relaxed font-sans">
              <strong>Mandatory Re-Verification Policy:</strong> Resolving an open alert triggers backend re-verification of file digests. If physical disk bytes remain corrupt, the backend will reject resolution.
            </div>

            {resolutionError && (
              <div className="p-3 bg-red-100 border border-red-300 text-red-900 text-xs rounded-xl font-mono">
                {resolutionError}
              </div>
            )}

            <form onSubmit={handleResolveSubmit} className="space-y-4">
              <div>
                <label className="block text-slate-700 font-semibold text-xs mb-1 uppercase tracking-wider">
                  Resolution Note / Audit Justification
                </label>
                <textarea
                  rows={3}
                  required
                  value={resolutionReason}
                  onChange={(e) => setResolutionReason(e.target.value)}
                  placeholder="Provide investigation details or physical restoration confirmation..."
                  className="w-full rounded-xl border border-slate-300 p-2.5 text-xs text-slate-900 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setResolvingAlert(null)}
                  className="px-4 py-2 rounded-xl text-slate-600 hover:bg-slate-100 text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isResolving || !resolutionReason.trim()}
                  className="px-4 py-2 rounded-xl bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 disabled:opacity-50"
                >
                  {isResolving ? 'Re-Verifying...' : 'Re-Verify & Resolve Alert'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
