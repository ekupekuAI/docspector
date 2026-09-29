import React, { useEffect, useState } from 'react';
import { Check, X } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { TransferRecord } from '../types';
import { StatusBadge } from '../components/status/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

export const TransfersPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();

  const [transfers, setTransfers] = useState<TransferRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actioningId, setActioningId] = useState<number | null>(null);

  useEffect(() => {
    fetchTransfers();
  }, []);

  const fetchTransfers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getTransfer(1).then((res) => [res]).catch(() => []);
      setTransfers(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch transfers queue.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDecision = async (transferId: number, action: 'approve' | 'reject' | 'revoke') => {
    setActioningId(transferId);
    try {
      if (action === 'approve') {
        await api.approveTransfer(transferId);
        showToast({ type: 'success', title: 'Transfer Approved', message: `Transfer #${transferId} approved successfully.` });
      } else if (action === 'reject') {
        await api.rejectTransfer(transferId);
        showToast({ type: 'warning', title: 'Transfer Rejected', message: `Transfer #${transferId} rejected.` });
      } else {
        await api.revokeTransfer(transferId);
        showToast({ type: 'warning', title: 'Transfer Revoked', message: `Transfer #${transferId} revoked.` });
      }
      fetchTransfers();
    } catch (err) {
      if (err instanceof ApiError) {
        showToast({ type: 'error', title: 'Action Failed', message: err.message });
      } else {
        showToast({ type: 'error', title: 'Error', message: 'Network error executing transfer decision.' });
      }
    } finally {
      setActioningId(null);
    }
  };

  const isSO = user?.role === 'SO';
  const isIO = user?.role === 'IO';

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
          Transfer Workflow
        </p>
        <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Transfer Center</h1>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-sm animate-pulse">
          Loading transfers queue...
        </div>
      ) : transfers.length === 0 ? (
        <EmptyState
          title="No active transfers"
          description="No transfer records are currently registered or awaiting review."
        />
      ) : (
        <div className="space-y-4">
          {transfers.map((transfer) => {
            const isPending = transfer.status === 'PENDING';
            const canApprove = isSO && isPending;
            const canRevoke = isIO && isPending;

            return (
              <div
                key={transfer.id}
                className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft card-interactive"
              >
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 font-mono">
                      Transfer ID: #{transfer.id} • Document #{transfer.document_id}
                    </div>
                    <div className="mt-2 text-xl font-bold text-slate-900 font-mono">
                      Version #{transfer.document_version_id}
                    </div>
                    <div className="mt-2 text-sm text-slate-600">
                      From: User #{transfer.requester_user_id} • To: User #{transfer.recipient_user_id} • Requested: {new Date(transfer.requested_at).toLocaleString()}
                    </div>
                  </div>
                  <StatusBadge status={transfer.status} />
                </div>

                <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs font-mono text-slate-700">
                  Case ID: #{transfer.case_id} • Recipient User ID: #{transfer.recipient_user_id}
                </div>

                {canApprove && (
                  <div className="mt-4 flex flex-wrap gap-3">
                    <button
                      type="button"
                      disabled={actioningId === transfer.id}
                      onClick={() => handleDecision(transfer.id, 'approve')}
                      className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-emerald-700 transition disabled:opacity-50"
                    >
                      <Check className="h-4 w-4" /> Approve
                    </button>
                    <button
                      type="button"
                      disabled={actioningId === transfer.id}
                      onClick={() => handleDecision(transfer.id, 'reject')}
                      className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-700 transition disabled:opacity-50"
                    >
                      <X className="h-4 w-4" /> Reject
                    </button>
                  </div>
                )}

                {canRevoke && (
                  <div className="mt-4 flex flex-wrap gap-3">
                    <button
                      type="button"
                      disabled={actioningId === transfer.id}
                      onClick={() => handleDecision(transfer.id, 'revoke')}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-100 transition disabled:opacity-50"
                    >
                      Revoke Transfer
                    </button>
                  </div>
                )}

                {isIO && isPending && (
                  <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                    Transfer approval requires Supervisory Officer (SO) role authority.
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
