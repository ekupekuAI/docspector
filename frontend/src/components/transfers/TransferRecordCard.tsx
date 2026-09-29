import React, { useState } from 'react';
import { TransferRecord } from '../../types';
import { StatusBadge } from '../status/StatusBadge';
import { Button } from '../ui/Button';
import { api, ApiError } from '../../api/client';
import { useToast } from '../../context/ToastContext';

interface TransferRecordCardProps {
  transfer: TransferRecord;
  currentUserRole?: string;
  onStateChange?: (updated: TransferRecord) => void;
  documentTitle?: string;
}

export const TransferRecordCard: React.FC<TransferRecordCardProps> = ({
  transfer,
  currentUserRole,
  onStateChange,
  documentTitle,
}) => {
  const { showToast } = useToast();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);

  const isSO = currentUserRole === 'SO';

  const handleApprove = async () => {
    setIsProcessing(true);
    setError(null);
    try {
      const updated = await api.approveTransfer(transfer.id);
      showToast({
        type: 'success',
        title: 'Transfer Approved',
        message: `Transfer #${transfer.id} approved. Custody delegated to Recipient User #${transfer.recipient_user_id}.`,
      });
      onStateChange?.(updated);
    } catch (err) {
      handleApiError(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleReject = async () => {
    setIsProcessing(true);
    setError(null);
    try {
      const updated = await api.rejectTransfer(transfer.id);
      showToast({
        type: 'info',
        title: 'Transfer Rejected',
        message: `Transfer #${transfer.id} has been formally rejected.`,
      });
      onStateChange?.(updated);
    } catch (err) {
      handleApiError(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRevoke = async () => {
    setIsProcessing(true);
    setError(null);
    try {
      const updated = await api.revokeTransfer(transfer.id);
      setShowRevokeConfirm(false);
      showToast({
        type: 'warning',
        title: 'Transfer Revoked',
        message: `Custody delegation for Transfer #${transfer.id} has been revoked.`,
      });
      onStateChange?.(updated);
    } catch (err) {
      handleApiError(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleApiError = async (err: unknown) => {
    if (err instanceof ApiError) {
      if (err.status === 401) {
        setError('Your session has expired. Please sign in again.');
      } else if (err.status === 403) {
        setError('You are not authorized to perform this transfer action.');
      } else if (err.status === 404) {
        setError('Transfer record not found.');
      } else if (err.status === 409) {
        setError(
          'Transfer state changed before your action completed. Refreshing the transfer record.'
        );
        try {
          const fresh = await api.getTransfer(transfer.id);
          onStateChange?.(fresh);
        } catch {
          // Keep error message
        }
      } else if (err.status === 422) {
        setError('Transfer action could not be processed.');
      } else if (err.status === 429) {
        setError('Too many requests. Please wait before trying again.');
      } else {
        setError(err.message || 'Transfer operation failed. Please try again.');
      }
    } else {
      setError('Network or system error occurred.');
    }
  };

  const formatDate = (isoString?: string | null) => {
    if (!isoString) return '—';
    try {
      return new Date(isoString).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4 hover:border-slate-700 transition-all shadow-sm">
      {/* Top Header: Transfer ID, Document/Version Scope, and Status */}
      <div className="flex items-start justify-between gap-4 flex-wrap pb-3.5 border-b border-slate-800/80">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono font-bold text-slate-300 bg-slate-950 px-3 py-1 rounded-md border border-slate-800">
              TRANSFER #{transfer.id}
            </span>
            <StatusBadge status={transfer.status} />
          </div>

          <div className="flex items-center gap-2.5 text-sm flex-wrap pt-0.5">
            <span className="font-mono font-bold text-slate-100">
              DOC-{String(transfer.document_id).padStart(4, '0')}
            </span>
            {documentTitle && (
              <span className="text-slate-400 text-xs truncate max-w-xs" title={documentTitle}>
                ({documentTitle})
              </span>
            )}
            <span className="text-slate-600 font-light">|</span>
            <span className="bg-indigo-950/80 border border-indigo-700/80 text-indigo-300 font-mono text-xs font-bold px-3 py-0.5 rounded-md">
              Version Scope: ID #{transfer.document_version_id}
            </span>
          </div>
        </div>

        {/* State Banner / Explanatory Text */}
        <div className="text-right">
          {transfer.status === 'PENDING' && (
            <span className="text-xs text-amber-300 font-mono font-medium flex items-center gap-1.5 bg-amber-950/50 border border-amber-800/70 px-3 py-1.5 rounded-lg">
              <span>⏱</span>
              <span>Awaiting supervisory review</span>
            </span>
          )}
          {transfer.status === 'APPROVED' && (
            <span className="text-xs text-emerald-300 font-mono font-medium flex items-center gap-1.5 bg-emerald-950/50 border border-emerald-800/70 px-3 py-1.5 rounded-lg">
              <span>✓</span>
              <span>Transfer workflow approved</span>
            </span>
          )}
          {transfer.status === 'REJECTED' && (
            <span className="text-xs text-rose-300 font-mono font-medium flex items-center gap-1.5 bg-rose-950/50 border border-rose-800/70 px-3 py-1.5 rounded-lg">
              <span>✕</span>
              <span>Transfer workflow rejected</span>
            </span>
          )}
          {transfer.status === 'REVOKED' && (
            <span className="text-xs text-slate-400 font-mono font-medium flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              <span>⊘</span>
              <span>Transfer revoked</span>
            </span>
          )}
        </div>
      </div>

      {/* Transfer Details Audit Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs bg-slate-950/80 p-4 rounded-lg border border-slate-800">
        <div>
          <span className="text-slate-400 block text-xs font-semibold mb-1">Requester (Origin)</span>
          <span className="font-mono text-slate-200 font-bold flex items-center gap-1 text-sm">
            User #{transfer.requester_user_id}
          </span>
        </div>

        <div>
          <span className="text-slate-400 block text-xs font-semibold mb-1">Recipient (Target)</span>
          <span className="font-mono text-cyan-300 font-bold flex items-center gap-1 text-sm">
            User #{transfer.recipient_user_id}
          </span>
        </div>

        <div>
          <span className="text-slate-400 block text-xs font-semibold mb-1">Requested Timestamp</span>
          <span className="text-slate-300 font-mono text-xs">
            {formatDate(transfer.requested_at)}
          </span>
        </div>

        <div>
          <span className="text-slate-400 block text-xs font-semibold mb-1">
            {transfer.status === 'REVOKED' ? 'Revoked Timestamp' : 'Decision Timestamp'}
          </span>
          <span className="text-slate-300 font-mono text-xs">
            {transfer.status === 'REVOKED'
              ? formatDate(transfer.revoked_at)
              : formatDate(transfer.decided_at)}
          </span>
        </div>
      </div>

      {/* Decision Actor Info if available */}
      {transfer.decided_by_user_id && (
        <div className="text-xs text-slate-400 flex items-center gap-2 px-1 font-mono">
          <span className="text-slate-400 font-semibold">Decision Authorizer:</span>
          <span className="text-slate-200 font-bold">Supervisor User #{transfer.decided_by_user_id}</span>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/70 border border-red-700 text-red-100 text-xs">
          {error}
        </div>
      )}

      {/* Revocation Confirmation Dialog / Inline Banner */}
      {showRevokeConfirm && (
        <div className="p-4.5 bg-amber-950/60 border border-amber-700 rounded-lg space-y-2.5 animate-fade-in">
          <div className="text-xs font-bold text-amber-300 flex items-center gap-2 uppercase tracking-wider font-mono">
            <span>⚠ CONFIRM TRANSFER REVOCATION</span>
          </div>
          <p className="text-xs text-slate-200 leading-relaxed font-sans">
            This will revoke the approved transfer for <strong>DOC-{String(transfer.document_id).padStart(4, '0')} (Version ID #{transfer.document_version_id})</strong> to Recipient User #{transfer.recipient_user_id}.
          </p>
          <div className="flex items-center gap-2.5 pt-1">
            <Button
              variant="danger"
              size="sm"
              onClick={handleRevoke}
              disabled={isProcessing}
              isLoading={isProcessing}
            >
              Confirm Revocation
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowRevokeConfirm(false)}
              disabled={isProcessing}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Action Controls */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
        <span className="text-xs text-slate-400 font-mono">
          {transfer.status === 'PENDING'
            ? 'Awaiting supervisory review decision'
            : 'Immutable custody ledger entry recorded'}
        </span>

        <div className="flex items-center gap-2.5">
          {transfer.status === 'PENDING' && (
            <>
              <Button
                variant="primary"
                size="sm"
                onClick={handleApprove}
                disabled={isProcessing}
                isLoading={isProcessing}
                title={isSO ? 'Approve transfer request' : 'Submit approval (backend authorization authoritative)'}
              >
                ✓ Approve
              </Button>

              <Button
                variant="danger"
                size="sm"
                onClick={handleReject}
                disabled={isProcessing}
                isLoading={isProcessing}
                title={isSO ? 'Reject transfer request' : 'Submit rejection (backend authorization authoritative)'}
              >
                ✕ Reject
              </Button>
            </>
          )}

          {transfer.status === 'APPROVED' && !showRevokeConfirm && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowRevokeConfirm(true)}
              disabled={isProcessing}
              title="Revoke approved transfer"
            >
              ↺ Revoke Transfer
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};
