import React, { useState } from 'react';
import { DocumentRecord, DocumentVersionRecord, DemoTamperResponse } from '../../types';
import { api, ApiError } from '../../api/client';
import { Button } from '../ui/Button';

interface DemoTamperModalProps {
  document: DocumentRecord;
  version: DocumentVersionRecord;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (resp: DemoTamperResponse) => void;
}

export const DemoTamperModal: React.FC<DemoTamperModalProps> = ({
  document: doc,
  version,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSimulate = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      const resp = await api.simulateTamper(doc.id, version.id);
      onSuccess(resp);
      onClose();
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setError(
            'Controlled tamper simulation is unavailable. Verify that DEMO_MODE is enabled on the server and that your account is an assigned case officer (IO/SO).'
          );
        } else if (err.status === 404) {
          setError('Document or version record not found on server.');
        } else {
          setError(err.message || 'Tamper simulation failed.');
        }
      } else {
        setError('Network error occurred during tamper simulation.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto animate-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="tamper-modal-title"
    >
      <div className="relative w-full max-w-lg bg-slate-900 border border-amber-800/80 rounded-xl shadow-2xl overflow-hidden animate-modal-content">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-amber-900/60 bg-amber-950/40 flex items-center justify-between">
          <div className="flex items-center gap-2 text-amber-400">
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-950 border border-amber-800 text-amber-300">
              DEMO MODE
            </span>
            <h2 id="tamper-modal-title" className="text-base font-bold text-slate-100">
              Controlled Tamper Simulation
            </h2>
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
        <div className="p-6 space-y-5 text-xs text-slate-300">
          <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/60 text-amber-200 text-xs leading-relaxed">
            <strong>Simulation Guard Notice:</strong> This operation performs a synthetic, controlled file byte modification in private storage for the purpose of demonstrating Docspector's automated hash-integrity detection workflow.
          </div>

          {/* Exact Target Information */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">
              Simulation Target
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px]">Document</span>
                <span className="text-slate-200 font-bold">
                  {doc.document_number || `DOC-${String(doc.id).padStart(4, '0')}`}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Exact Version</span>
                <span className="text-amber-300 font-bold">Version V{version.version_number}</span>
                <span className="text-slate-500 text-[10px] block">ID: #{version.id}</span>
              </div>
            </div>
            <div className="pt-1 text-[11px] text-slate-400 truncate">
              File: <span className="text-slate-200">{version.original_filename}</span>
            </div>
          </div>

          {/* Workflow Sequence Explanation */}
          <div className="p-3 bg-slate-950/50 rounded border border-slate-800/80 space-y-1.5 text-[11px] text-slate-400">
            <span className="text-slate-300 font-semibold block">Expected Demo Lifecycle:</span>
            <ol className="list-decimal list-inside space-y-1 font-mono text-[10px]">
              <li>Appends synthetic demo bytes to physical private storage.</li>
              <li>Database SHA-256 hash remains unmodified (evidence preserved).</li>
              <li>Running <strong>Verify Integrity</strong> will compute the hash mismatch and restrict the version.</li>
            </ol>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3 rounded bg-red-950/50 border border-red-800 text-red-200 text-xs">
              {error}
            </div>
          )}

          {/* Action Buttons */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
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
              type="button"
              variant="danger"
              size="sm"
              onClick={handleSimulate}
              disabled={isSubmitting}
              isLoading={isSubmitting}
            >
              {isSubmitting ? 'Modifying Storage Bytes...' : 'Simulate Tampering ⚠'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
