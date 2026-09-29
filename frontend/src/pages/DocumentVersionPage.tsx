import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { CheckCircle2, ShieldAlert } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { DocumentCustodyResponse, VerificationResponse } from '../types';
import { StatusBadge } from '../components/status/StatusBadge';
import { HashDisplay } from '../components/ui/HashDisplay';
import { EmptyState } from '../components/ui/EmptyState';

export const DocumentVersionPage: React.FC = () => {
  const { documentId, versionId } = useParams<{ documentId: string; versionId: string }>();
  const [custodyData, setCustodyData] = useState<DocumentCustodyResponse | null>(null);
  const [verificationResult, setVerificationResult] = useState<VerificationResponse | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (documentId) {
      fetchVersionDetails();
    }
  }, [documentId, versionId]);

  const fetchVersionDetails = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getDocumentCustody(Number(documentId));
      setCustodyData(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch version custody details.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!documentId || !versionId) return;
    setIsVerifying(true);
    try {
      const resp = await api.verifyDocumentVersion(Number(documentId), Number(versionId));
      setVerificationResult(resp);
    } catch (err) {
      // error handling
    } finally {
      setIsVerifying(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
        Loading version specifications...
      </div>
    );
  }

  if (error || !custodyData) {
    return (
      <EmptyState
        title="Version not found"
        description={error || "This version is not available in the evidence chain."}
      />
    );
  }

  const versionEvents = custodyData.events.filter(
    (e) => e.document_version_id === Number(versionId)
  );
  const recordedHash = versionEvents[0]?.event_hash || custodyData.events[0]?.event_hash || 'SHA-256 Digest';
  const isRestricted = verificationResult?.overall_status === 'INTEGRITY_FAILURE';

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* Version Card Header */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
              Version Specification
            </p>
            <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">
              {custodyData.document_number} — Version V{versionId}
            </h1>
          </div>
          <StatusBadge status={isRestricted ? 'RESTRICTED' : 'STORED'} />
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">Version ID</div>
            <div className="mt-1 font-medium text-slate-800 font-mono">#{versionId}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Document ID</div>
            <div className="mt-1 font-medium text-slate-800 font-mono">#{documentId}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Status</div>
            <div className="mt-1 font-medium text-slate-800">{isRestricted ? 'RESTRICTED' : 'STORED'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-[0.15em] text-slate-500">Actions</div>
            <div className="mt-1">
              <button
                onClick={handleVerify}
                disabled={isVerifying}
                className="rounded-lg bg-blue-600 text-white px-3 py-1 text-xs font-semibold hover:bg-blue-700 transition"
              >
                {isVerifying ? 'Verifying...' : 'Verify Version Integrity'}
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6">
          <HashDisplay hash={recordedHash} label="RECORDED SHA-256" />
        </div>
      </div>

      {/* Verification Result Notification */}
      {verificationResult && (
        <div
          className={`rounded-2xl border p-5 shadow-soft ${
            verificationResult.overall_status === 'VALID'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
              : 'border-red-200 bg-red-50 text-red-900'
          }`}
        >
          <div className="flex items-center gap-2 font-bold text-sm uppercase">
            <CheckCircle2 className="h-5 w-5" />
            <span>Integrity Result: {verificationResult.overall_status}</span>
          </div>
          <div className="mt-2 text-xs font-mono">
            File Bytes: {verificationResult.file_integrity.is_valid ? 'VALID' : 'CORRUPTED / MISMATCH'} | Custody Chain: {verificationResult.chain_integrity.is_valid ? 'VALID' : 'BROKEN'}
          </div>
        </div>
      )}

      {/* Version History List Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
        <div className="mb-4 flex items-center gap-2">
          <CheckCircle2 className="h-5 w-5 text-emerald-600" />
          <h3 className="text-xl font-bold text-slate-900">Version history</h3>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="rounded-xl border border-blue-500 bg-blue-50 p-3">
            <div className="font-bold text-slate-900 font-mono">Version V{versionId}</div>
            <div className="mt-1 text-xs text-slate-500">{isRestricted ? 'RESTRICTED' : 'STORED'}</div>
          </div>
        </div>
      </div>

      {isRestricted && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-5 text-red-800 shadow-soft">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-600" />
            <span className="font-bold">Access restricted</span>
          </div>
          <p className="mt-2 text-sm text-red-700 font-sans">
            This version remains restricted after integrity review and cannot be restored to VALID without backend confirmation.
          </p>
        </div>
      )}
    </div>
  );
};
