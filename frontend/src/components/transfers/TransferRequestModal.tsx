import React from 'react';
import { DocumentRecord, DocumentVersionRecord, TransferRecord } from '../../types';
import { api, ApiError } from '../../api/client';
import { Button } from '../ui/Button';

interface TransferRequestModalProps {
  document: DocumentRecord;
  version: DocumentVersionRecord;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (transfer: TransferRecord) => void;
}

// Known default investigator / supervisory users for ease of selection in air-gapped demo
const RECIPIENT_PRESETS = [
  { id: 2, label: 'Supervisor Officer (SO) — ID #2', username: 'docspector.so' },
  { id: 1, label: 'Investigating Officer (IO) — ID #1', username: 'docspector.io' },
  { id: 3, label: 'Legal Reviewer — ID #3', username: 'docspector.legal' },
  { id: 4, label: 'Auditor — ID #4', username: 'docspector.auditor' },
];

export const TransferRequestModal: React.FC<TransferRequestModalProps> = ({
  document: doc,
  version,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [recipientId, setRecipientId] = React.useState<number>(2);
  const [customRecipient, setCustomRecipient] = React.useState<string>('');
  const [isCustom, setIsCustom] = React.useState(false);
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  if (!isOpen) return null;

  const isRestricted = version.state === 'RESTRICTED';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isRestricted) {
      setError('Cannot request transfer: This document version is RESTRICTED.');
      return;
    }

    const targetRecipientId = isCustom ? parseInt(customRecipient, 10) : recipientId;
    if (isNaN(targetRecipientId) || targetRecipientId <= 0) {
      setError('Please provide a valid numeric recipient user ID.');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const transfer = await api.requestTransfer(doc.id, version.id, targetRecipientId);
      onSuccess(transfer);
      onClose();
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError('Your session has expired. Please sign in again.');
        } else if (err.status === 403) {
          setError('You are not authorized to request custody transfers for this document version.');
        } else if (err.status === 404) {
          setError('Document or version record not found.');
        } else if (err.status === 409) {
          setError('A transfer request is already pending for this version or the record is in a conflicting state.');
        } else if (err.status === 422) {
          setError('Transfer request could not be processed. Please check input parameters.');
        } else {
          setError(err.message || 'Transfer operation failed. Please try again.');
        }
      } else {
        setError('Network or system error occurred. Please verify backend connection.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto animate-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="transfer-modal-title"
    >
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden animate-modal-content">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400">
            <span className="text-base font-semibold text-slate-100" id="transfer-modal-title">
              ⇄ Request Custody Transfer
            </span>
          </div>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            className="text-slate-400 hover:text-slate-200 transition-colors text-xl font-bold px-2 py-0.5 rounded"
            aria-label="Close dialog"
          >
            &times;
          </button>
        </div>

        {/* Modal Content */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Restricted Warning if blocked */}
          {isRestricted ? (
            <div className="p-4 rounded-lg bg-red-950/40 border border-red-800/80 text-red-200 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-red-400">
                <span>🔴 TRANSFER BLOCKED</span>
              </div>
              <p className="text-xs text-red-300 leading-relaxed">
                Integrity verification has placed this document version into a restricted state. Custody transfers cannot be initiated for restricted document versions.
              </p>
            </div>
          ) : (
            <div className="p-3.5 rounded-lg bg-cyan-950/30 border border-cyan-800/50 text-cyan-200 text-xs flex items-start gap-2.5">
              <span>
                Custody transfer requests are scoped strictly to the specified document version and require supervisory authorization.
              </span>
            </div>
          )}

          {/* Exact Version Scope Panel */}
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Exact Transfer Scope
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800/80">
                <span className="text-slate-400 block text-[11px]">Document</span>
                <span className="text-slate-200 font-medium font-mono">
                  {doc.document_number || `DOC-${String(doc.id).padStart(4, '0')}`}
                </span>
                <span className="text-slate-400 block truncate mt-0.5 text-[11px]" title={doc.title}>
                  {doc.title}
                </span>
              </div>

              <div className="bg-slate-900/80 p-2.5 rounded border border-cyan-800/40">
                <span className="text-cyan-400 block text-[11px] font-semibold">Exact Version Scope</span>
                <span className="text-cyan-300 font-bold font-mono text-sm">
                  V{version.version_number}
                </span>
                <span className="text-slate-400 block text-[10px] font-mono truncate mt-0.5" title={`Version ID: ${version.id}`}>
                  ID: #{version.id}
                </span>
              </div>
            </div>

            <div className="text-[11px] text-amber-300/90 bg-amber-950/30 border border-amber-900/40 p-2 rounded">
              <strong>Scope Notice:</strong> This custody transfer applies exclusively to <strong>Version V{version.version_number}</strong>. It does NOT transfer unapproved versions or wildcard latest versions.
            </div>
          </div>

          {/* Recipient Selection */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-300">
              Recipient User (Custody Target)
            </label>
            
            <div className="space-y-2">
              {!isCustom ? (
                <select
                  value={recipientId}
                  onChange={(e) => setRecipientId(Number(e.target.value))}
                  disabled={isRestricted || isSubmitting}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  {RECIPIENT_PRESETS.map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.label}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="number"
                  min="1"
                  placeholder="Enter numeric Recipient User ID"
                  value={customRecipient}
                  onChange={(e) => setCustomRecipient(e.target.value)}
                  disabled={isRestricted || isSubmitting}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                />
              )}

              <button
                type="button"
                onClick={() => setIsCustom(!isCustom)}
                className="text-xs text-cyan-400 hover:text-cyan-300 underline block"
              >
                {isCustom ? '← Select from known investigator roles' : '+ Enter custom User ID'}
              </button>
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-800 text-red-200 text-xs">
              {error}
            </div>
          )}

          {/* Confirmation & Actions */}
          <div className="pt-2 border-t border-slate-800 flex items-center justify-end gap-3">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={isRestricted || isSubmitting}
              isLoading={isSubmitting}
            >
              {isSubmitting ? 'Requesting...' : 'Request Transfer →'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
