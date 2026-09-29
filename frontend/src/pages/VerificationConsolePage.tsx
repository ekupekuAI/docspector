import React, { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { VerificationResponse, DemoTamperResponse } from '../types';
import { useToast } from '../context/ToastContext';

export const VerificationConsolePage: React.FC = () => {
  const { showToast } = useToast();
  const [docIdInput, setDocIdInput] = useState<string>('1');
  const [versionIdInput, setVersionIdInput] = useState<string>('1');
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isTampering, setIsTampering] = useState<boolean>(false);
  const [result, setResult] = useState<VerificationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tamperSuccess, setTamperSuccess] = useState<string | null>(null);

  const handleVerify = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const docId = parseInt(docIdInput.trim(), 10);
    const versionId = parseInt(versionIdInput.trim(), 10);

    if (isNaN(docId) || docId <= 0 || isNaN(versionId) || versionId <= 0) {
      setError('Please provide valid positive numeric Document ID and Version ID.');
      return;
    }

    setIsVerifying(true);
    setError(null);

    try {
      const resp = await api.verifyDocumentVersion(docId, versionId);
      setResult(resp);

      if (resp.overall_status === 'VALID') {
        showToast({
          type: 'success',
          title: 'Integrity Verified',
          message: `Document #${docId} (Version #${versionId}) successfully verified.`,
        });
      } else {
        showToast({
          type: 'error',
          title: 'CRITICAL: Integrity Failure',
          message: `Physical hash mismatch for Document #${docId}. Version restricted.`,
        });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || 'Verification failed.');
      } else {
        setError('Network error during verification.');
      }
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamper = async () => {
    const docId = parseInt(docIdInput.trim(), 10);
    const versionId = parseInt(versionIdInput.trim(), 10);

    if (isNaN(docId) || docId <= 0 || isNaN(versionId) || versionId <= 0) {
      setError('Please provide valid positive numeric Document ID and Version ID.');
      return;
    }

    setIsTampering(true);
    setError(null);
    setTamperSuccess(null);

    try {
      const resp: DemoTamperResponse = await api.simulateTamper(docId, versionId);
      setTamperSuccess(
        `Synthetic storage bytes corrupted on disk for DOC-${docId} (V${resp.version_number}). Persisted DB hash preserved. Click "Verify Integrity" to execute automated detection.`
      );
      showToast({
        type: 'warning',
        title: 'Synthetic Corruption Applied (DEMO MODE)',
        message: `Physical file bytes corrupted on disk for Document #${docId}.`,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || 'Tamper simulation failed.');
      } else {
        setError('Network error during tamper simulation.');
      }
    } finally {
      setIsTampering(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
          Verification Subsystem
        </p>
        <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Verification & Audit Console</h1>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft space-y-5 card-interactive">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="text-sm font-bold text-slate-900 uppercase font-sans">
            Direct Document Version Inspection
          </div>
          <span className="text-xs font-mono text-slate-500">
            POST /api/v1/documents/&#123;id&#125;/versions/&#123;version_id&#125;/verify
          </span>
        </div>

        <form onSubmit={handleVerify} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase font-sans">
              Document Record ID
            </label>
            <input
              type="number"
              min="1"
              value={docIdInput}
              onChange={(e) => setDocIdInput(e.target.value)}
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-mono text-slate-900 outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase font-sans">
              Version Record ID
            </label>
            <input
              type="number"
              min="1"
              value={versionIdInput}
              onChange={(e) => setVersionIdInput(e.target.value)}
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-mono text-slate-900 outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-end gap-2.5">
            <button
              type="submit"
              disabled={isVerifying || isTampering}
              className="flex-1 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {isVerifying ? 'Verifying...' : 'Verify Integrity'}
            </button>

            <button
              type="button"
              onClick={handleTamper}
              disabled={isVerifying || isTampering}
              className="rounded-xl bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-700 transition disabled:opacity-50"
              title="Controlled Synthetic Tampering (DEMO MODE)"
            >
              {isTampering ? 'Corrupting...' : 'Tamper (DEMO)'}
            </button>
          </div>
        </form>

        {tamperSuccess && (
          <div className="p-4 rounded-xl border border-amber-200 bg-amber-50 text-amber-900 text-xs font-sans">
            <strong className="block font-bold mb-1 uppercase tracking-wider text-amber-800">
              DEMO TAMPER EXECUTED
            </strong>
            {tamperSuccess}
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl border border-red-200 bg-red-50 text-red-800 text-xs font-mono">
            {error}
          </div>
        )}
      </div>

      {result && (
        <div
          className={`rounded-2xl border p-5 shadow-soft font-sans ${
            result.overall_status === 'VALID'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
              : 'border-red-200 bg-red-50 text-red-900'
          }`}
        >
          <div className="flex items-center gap-2 font-bold text-sm uppercase">
            <ShieldCheck className="h-5 w-5" />
            <span>Overall Verification Result: {result.overall_status}</span>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-2 text-xs font-mono">
            <div className="p-3 bg-white/80 rounded-xl border border-slate-200">
              <div className="text-slate-500 font-bold uppercase">File Byte Integrity</div>
              <div className="mt-1 font-semibold">
                Status: {result.file_integrity.is_valid ? 'VALID' : 'HASH MISMATCH'}
              </div>
              <div className="mt-1 text-slate-600 truncate">Stored Digest: {result.file_integrity.stored_hash}</div>
            </div>

            <div className="p-3 bg-white/80 rounded-xl border border-slate-200">
              <div className="text-slate-500 font-bold uppercase">Custody Ledger Integrity</div>
              <div className="mt-1 font-semibold">
                Status: {result.chain_integrity.is_valid ? 'VALID' : 'BROKEN CHAIN'}
              </div>
              <div className="mt-1 text-slate-600">Total Events: {result.chain_integrity.total_events}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
