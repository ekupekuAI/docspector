import React, { useState, useEffect } from 'react';
import { VerificationResponse } from '../../types';
import { StatusBadge } from '../status/StatusBadge';
import { HashCopyBadge } from '../ui/HashCopyBadge';
import { formatFileSize } from '../../lib/format';
import { formatDateTime } from '../../lib/date';

interface IntegrityVerificationPanelProps {
  result: VerificationResponse;
  isVerifying?: boolean;
  onReverify?: () => void;
}

const VERIFICATION_STEPS = [
  { id: 1, label: 'VERIFYING FILE' },
  { id: 2, label: 'COMPUTING SHA-256' },
  { id: 3, label: 'VALIDATING CUSTODY CHAIN' },
  { id: 4, label: 'COMPARING INTEGRITY' },
];

export const IntegrityVerificationPanel: React.FC<IntegrityVerificationPanelProps> = ({
  result,
  isVerifying = false,
  onReverify,
}) => {
  const isOverallValid = result.overall_status === 'VALID';
  const isFileValid = result.file_integrity.is_valid;
  const isChainValid = result.chain_integrity.is_valid;
  const isRestricted = result.version_state === 'RESTRICTED';

  const [activeStep, setActiveStep] = useState<number>(4);

  useEffect(() => {
    if (isVerifying) {
      setActiveStep(1);
      const timer1 = setTimeout(() => setActiveStep(2), 160);
      const timer2 = setTimeout(() => setActiveStep(3), 320);
      const timer3 = setTimeout(() => setActiveStep(4), 480);
      return () => {
        clearTimeout(timer1);
        clearTimeout(timer2);
        clearTimeout(timer3);
      };
    } else {
      setActiveStep(4);
    }
  }, [isVerifying]);

  return (
    <div
      className={`rounded-2xl border-2 transition-all duration-300 p-6 sm:p-8 space-y-7 ${
        isOverallValid
          ? 'bg-slate-900/95 border-emerald-600 shadow-xl shadow-emerald-950/30 ring-1 ring-emerald-500/20 animate-success-enter'
          : 'bg-red-950/40 border-red-600 shadow-xl shadow-red-950/60 ring-1 ring-red-600/40 animate-failure-enter'
      }`}
      role="region"
      aria-label="Integrity Verification Command Console"
      aria-live="polite"
    >
      {/* Verification Step Progress Sequence */}
      {isVerifying && (
        <div className="p-5 rounded-xl bg-slate-950 border border-cyan-600/70 space-y-3 animate-fade-in">
          <div className="flex items-center justify-between">
            <span className="text-xs font-sans font-semibold uppercase tracking-wide text-cyan-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Verification Execution Sequence
            </span>
            <span className="text-xs font-sans text-slate-400">Processing...</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs font-sans">
            {VERIFICATION_STEPS.map((step) => {
              const isDone = activeStep > step.id;
              const isCurrent = activeStep === step.id;
              return (
                <div
                  key={step.id}
                  className={`p-2.5 rounded-lg border transition-all duration-200 flex items-center gap-2 ${
                    isDone
                      ? 'bg-cyan-950/90 border-cyan-500 text-cyan-200'
                      : isCurrent
                      ? 'bg-blue-900/80 border-blue-500 text-white font-bold ring-1 ring-blue-400/50'
                      : 'bg-slate-900 border-slate-800 text-slate-500'
                  }`}
                >
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    0{step.id}
                  </span>
                  <span className="truncate">{step.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* HERO HEADER: Overall Verification Status */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 pb-6 border-b border-slate-800 font-sans">
        <div className="space-y-2.5">
          <div className="flex items-center gap-3 flex-wrap">
            <div
              className={`inline-flex items-center gap-2.5 px-4 py-2 rounded-xl text-base font-bold tracking-wide uppercase shadow-md ${
                isOverallValid
                  ? 'bg-emerald-950 text-emerald-100 border-2 border-emerald-500'
                  : 'bg-red-950 text-red-100 border-2 border-red-500 shadow-red-950/80'
              }`}
            >
              <span className="text-xl select-none">{isOverallValid ? '✓' : '🔴'}</span>
              <span>{isOverallValid ? 'INTEGRITY VERIFIED' : 'INTEGRITY FAILURE'}</span>
            </div>

            <StatusBadge status={result.version_state} />

            {!isOverallValid && (
              <span className="px-3 py-1.5 rounded-lg bg-red-900/90 text-red-100 border border-red-600 text-xs font-mono font-bold tracking-wider uppercase">
                {result.file_integrity.status}
              </span>
            )}
          </div>

          <div className="text-sm text-slate-300 flex items-center gap-3 flex-wrap pt-1 font-sans">
            <span>
              Document Scope: <strong className="text-slate-100 font-mono">DOC-{String(result.document_id).padStart(4, '0')}</strong>
            </span>
            <span className="text-slate-600">|</span>
            <span>
              Target Version: <strong className="text-cyan-300 font-mono">Version V{result.version_number}</strong>
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400 font-mono">Version ID #{result.document_version_id}</span>
          </div>
        </div>

        {onReverify && (
          <button
            onClick={onReverify}
            disabled={isVerifying}
            className="self-start lg:self-center px-5 py-2.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-600 rounded-xl transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 flex items-center gap-2 shadow-md hover:border-slate-500 active:scale-[0.98] font-sans"
            title="Recompute on-disk SHA-256 and audit custody chain"
          >
            <span>{isVerifying ? 'Verifying...' : '↺ Recompute & Re-Verify'}</span>
          </button>
        )}
      </div>

      {/* HERO SECTION 1: PROMINENT INTEGRITY FAILURE / INCIDENT ALERT (IF CORRUPTED) */}
      {!isOverallValid && (
        <div
          className="p-6 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-100 space-y-4 shadow-xl shadow-red-950/80 animate-failure-enter"
          role="alert"
          aria-live="assertive"
        >
          <div className="flex items-center gap-3 font-bold text-red-200 text-lg font-sans">
            <span className="text-2xl">🔴</span>
            <span>CRITICAL ALERT: CRYPTOGRAPHIC INTEGRITY FAILURE</span>
          </div>

          <div className="p-4 bg-slate-950/90 rounded-lg border border-red-700 space-y-3 text-xs">
            <div className="text-amber-300 font-semibold text-sm font-sans">
              ⚠ DISCREPANCY DETECTED: Recorded SHA-256 Hash ≠ Current On-Disk Hash
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-red-950/40 rounded border border-red-800">
                <span className="text-slate-400 block text-[11px] font-semibold uppercase mb-1 font-sans">
                  Persisted Authoritative DB Digest
                </span>
                <span className="font-mono text-slate-200 break-all text-xs">
                  {result.file_integrity.stored_hash}
                </span>
              </div>

              <div className="p-3 bg-red-950/40 rounded border border-red-800">
                <span className="text-red-300 block text-[11px] font-semibold uppercase mb-1 font-sans">
                  On-Disk Recomputed Physical Digest
                </span>
                <span className="font-mono text-red-200 font-bold break-all text-xs">
                  {result.file_integrity.computed_hash || 'FILE MISSING / UNREADABLE'}
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs pt-1 font-sans">
            <div className="p-3 bg-red-950/60 rounded-lg border border-red-800">
              <span className="text-slate-400 block text-[11px] font-semibold uppercase">File Byte Integrity</span>
              <span className="font-bold text-red-200 mt-1 block font-mono">
                {result.file_integrity.status || 'FILE_HASH_MISMATCH'}
              </span>
            </div>
            <div className="p-3 bg-red-950/60 rounded-lg border border-red-800">
              <span className="text-slate-400 block text-[11px] font-semibold uppercase">Custody-Chain Integrity</span>
              <span className="font-bold text-emerald-400 mt-1 block font-mono">
                {isChainValid ? 'VALID (Chain Intact)' : 'CUSTODY CHAIN INVALID'}
              </span>
            </div>
            <div className="p-3 bg-red-950/60 rounded-lg border border-red-800">
              <span className="text-slate-400 block text-[11px] font-semibold uppercase">Document Version State</span>
              <span className="font-bold text-red-100 mt-1 block font-mono">
                {isRestricted ? 'RESTRICTED' : result.version_state}
              </span>
            </div>
          </div>

          <div className="space-y-1 text-xs text-red-200 leading-relaxed font-sans">
            <p>
              <strong>Security Protocol Enforced:</strong> Physical stored file bytes on disk no longer match the immutable cryptographic digest registered at ingestion. As a result:
            </p>
            <ul className="list-disc list-inside space-y-1 pl-2 text-red-100">
              <li>
                Document state transitioned to <strong className="font-mono">{isRestricted ? 'RESTRICTED' : result.version_state}</strong>.
              </li>
              <li>Successor version creation and custody transfers for this version are blocked.</li>
              <li>A critical security incident alert has been recorded in the platform ledger.</li>
            </ul>
          </div>
        </div>
      )}

      {/* HERO SECTION 2: VERIFIED STATE HERO SUMMARY (IF VALID) */}
      {isOverallValid && (
        <div className="p-6 rounded-xl bg-slate-950/90 border-2 border-emerald-700/80 space-y-4 font-sans">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-emerald-400">
              Verified Physical SHA-256 Digest
            </span>
            <span className="text-xs text-emerald-300 font-semibold">
              ✓ Exact 256-Bit Cryptographic Match
            </span>
          </div>

          <div className="p-4 bg-slate-900 rounded-lg border border-emerald-800/60">
            <HashCopyBadge
              hash={result.file_integrity.stored_hash}
              label="Authoritative SHA-256 Digest"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[11px] block font-semibold uppercase">FILE BYTE INTEGRITY</span>
              <span className="font-bold text-emerald-400 mt-1 block font-mono">VALID (Bytes Match Digest)</span>
            </div>
            <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[11px] block font-semibold uppercase">CUSTODY-CHAIN INTEGRITY</span>
              <span className="font-bold text-emerald-400 mt-1 block font-mono">VALID (Continuous Ledger)</span>
            </div>
            <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[11px] block font-semibold uppercase">DOCUMENT VERSION STATE</span>
              <span className="font-bold text-slate-100 mt-1 block font-mono">STORED</span>
            </div>
          </div>
        </div>
      )}

      {/* TWO INDEPENDENT VERIFICATION DIMENSIONS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-sans">
        {/* Dimension 1: Physical File Byte Integrity */}
        <div
          className={`p-6 rounded-xl border space-y-4 text-xs ${
            isFileValid
              ? 'bg-slate-950/90 border-slate-800'
              : 'bg-red-950/50 border-red-700 text-red-100 shadow-md'
          }`}
        >
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
              1. File Byte Integrity Subsystem
            </span>
            <span
              className={`font-bold px-3 py-1 rounded-lg text-xs font-mono ${
                isFileValid
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  : 'bg-red-950 text-red-200 border border-red-500'
              }`}
            >
              {result.file_integrity.status}
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <span className="text-slate-400 block text-xs mb-1 font-semibold">Persisted DB Hash:</span>
              <HashCopyBadge hash={result.file_integrity.stored_hash} label="DB Hash" />
            </div>

            {result.file_integrity.computed_hash && (
              <div>
                <span
                  className={`block text-xs mb-1 font-semibold ${
                    isFileValid ? 'text-slate-400' : 'text-red-300 font-semibold'
                  }`}
                >
                  On-Disk Recomputed Hash:
                </span>
                <HashCopyBadge
                  hash={result.file_integrity.computed_hash}
                  label="Disk Hash"
                />
              </div>
            )}

            <div className="flex items-center justify-between text-xs text-slate-300 pt-2 border-t border-slate-800/80">
              <span>Expected File Size: <strong className="font-mono">{formatFileSize(result.file_integrity.expected_size_bytes)}</strong></span>
              {result.file_integrity.actual_size_bytes !== null &&
                result.file_integrity.actual_size_bytes !== undefined && (
                  <span
                    className={
                      result.file_integrity.actual_size_bytes !==
                      result.file_integrity.expected_size_bytes
                        ? 'text-red-300 font-bold'
                        : ''
                    }
                  >
                    Actual File Size: <strong className="font-mono">{formatFileSize(result.file_integrity.actual_size_bytes)}</strong>
                  </span>
                )}
            </div>

            {result.file_integrity.error_message && (
              <div className="p-3.5 rounded-lg bg-red-950 border border-red-600 text-red-200 text-xs mt-2 leading-relaxed">
                <strong>Discrepancy Details:</strong> {result.file_integrity.error_message}
              </div>
            )}
          </div>
        </div>

        {/* Dimension 2: Hash-Chained Custody Chain Integrity */}
        <div
          className={`p-6 rounded-xl border space-y-4 text-xs ${
            isChainValid
              ? 'bg-slate-950/90 border-slate-800'
              : 'bg-red-950/50 border-red-700 text-red-100 shadow-md'
          }`}
        >
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
              2. Custody-Chain Ledger Integrity
            </span>
            <span
              className={`font-bold px-3 py-1 rounded-lg text-xs font-mono ${
                isChainValid
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  : 'bg-red-950 text-red-200 border border-red-500'
              }`}
            >
              {result.chain_integrity.status}
            </span>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-200">
              <span className="text-slate-400">Total Custody Events in Chain:</span>
              <span className="font-bold text-slate-100 font-mono text-sm">
                {result.chain_integrity.total_events}
              </span>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-200">
              <span className="text-slate-400">Ledger Structure:</span>
              <span className="text-cyan-300 font-medium">
                Continuous SHA-256 Hash Chain
              </span>
            </div>

            {result.chain_integrity.broken_sequence_number !== null &&
              result.chain_integrity.broken_sequence_number !== undefined && (
                <div className="text-xs text-red-200 font-bold bg-red-950 p-3 rounded-lg border border-red-600">
                  Broken Sequence Event: #{result.chain_integrity.broken_sequence_number}
                </div>
              )}

            {result.chain_integrity.error_message && (
              <div className="p-3.5 rounded-lg bg-red-950 border border-red-600 text-red-200 text-xs mt-2 leading-relaxed">
                <strong>Chain Ledger Error:</strong> {result.chain_integrity.error_message}
              </div>
            )}

            {isChainValid && (
              <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-700/60 text-emerald-200 text-xs leading-relaxed font-sans">
                ✓ Cryptographic hash chaining validated successfully across all{' '}
                <span className="font-mono">{result.chain_integrity.total_events}</span> recorded custody events.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Critical Integrity Alerts List */}
      {result.alerts && result.alerts.length > 0 && (
        <div className="space-y-3 pt-3 border-t border-slate-800 font-sans" role="alert">
          <div className="text-xs font-semibold text-red-400 uppercase tracking-wide flex items-center gap-2">
            <span>🔴 ACTIVE INTEGRITY SECURITY ALERTS ({result.alerts.length})</span>
          </div>

          <div className="space-y-3">
            {result.alerts.map((alert) => (
              <div
                key={alert.id}
                className="p-4 bg-red-950/70 border border-red-600/90 rounded-xl text-xs space-y-2 shadow-md shadow-red-950/60 animate-alert-attention"
              >
                <div className="flex items-center justify-between gap-3 flex-wrap font-sans">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2.5 py-0.5 bg-red-900 text-white text-xs font-bold rounded">
                      {alert.severity}
                    </span>
                    <span className="text-red-100 font-semibold text-sm">{alert.alert_type}</span>
                  </div>
                  <span className="text-slate-300 text-xs font-mono">
                    {formatDateTime(alert.created_at)}
                  </span>
                </div>
                <p className="text-slate-100 text-xs leading-relaxed font-sans">{alert.message}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Nonclaims Legal Disclaimer Notice */}
      <div className="text-xs text-slate-400 font-sans border-t border-slate-800 pt-4 leading-relaxed">
        <strong className="text-slate-300">Trust & Nonclaims Model:</strong> Docspector provides
        application-level cryptographic verification of stored file bytes against recorded SHA-256
        digests and hash-chained custody events. Verification asserts that stored bytes match recorded
        digests; it does not constitute a legal determination of document truthfulness, author intent,
        or judicial admissibility.
      </div>
    </div>
  );
};
