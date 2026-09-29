import React, { useState } from 'react';
import { DocumentRecord, DocumentVersionRecord } from '../../types';
import { StatusBadge } from '../status/StatusBadge';
import { Card, CardHeader, CardTitle } from './Card';
import { Button } from './Button';
import { Badge } from './Badge';
import { HashCopyBadge } from './HashCopyBadge';
import { formatDateTime } from '../../lib/date';
import { formatFileSize } from '../../lib/format';

export interface DocumentRecordCardProps {
  document: DocumentRecord;
  versionHistory?: DocumentVersionRecord[];
  onUploadSuccessor?: (documentId: number) => void;
  isUploadingSuccessor?: boolean;
  onRequestTransfer?: (document: DocumentRecord, version: DocumentVersionRecord) => void;
  onVerifyVersion?: (document: DocumentRecord, version: DocumentVersionRecord) => void;
  onSimulateTamper?: (document: DocumentRecord, version: DocumentVersionRecord) => void;
}

export const DocumentRecordCard: React.FC<DocumentRecordCardProps> = ({
  document,
  versionHistory = [],
  onUploadSuccessor,
  isUploadingSuccessor = false,
  onRequestTransfer,
  onVerifyVersion,
  onSimulateTamper,
}) => {
  const [showHistory, setShowHistory] = useState(false);
  const currentVersion = document.current_version;
  const isRestricted = currentVersion?.state === 'RESTRICTED';

  // Format MIME display
  const getMimeLabel = (mime?: string) => {
    if (!mime) return 'File';
    if (mime.includes('pdf')) return 'PDF Document';
    if (mime.includes('png')) return 'PNG Image';
    if (mime.includes('plain')) return 'Plain Text (UTF-8)';
    return mime.toUpperCase();
  };

  return (
    <Card
      className={`transition-all duration-200 ${
        isRestricted
          ? 'border-2 border-red-600 bg-red-950/30 shadow-xl shadow-red-950/70 ring-1 ring-red-600/40'
          : 'bg-slate-900/90 border-slate-800 hover:border-slate-700 shadow-md'
      }`}
    >
      {/* Card Header */}
      <CardHeader className="pb-4 border-b border-slate-800/90">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="text-xs font-mono tracking-wider text-cyan-400 font-bold px-2.5 py-1 bg-slate-950 rounded-md border border-slate-800">
              {document.document_number}
            </span>
            {currentVersion && (
              <Badge variant="info">
                Version V{currentVersion.version_number}
              </Badge>
            )}
            <span className="text-xs font-mono text-slate-400">
              ID: #{document.id}
            </span>
          </div>
          <CardTitle className="text-lg sm:text-xl font-bold text-slate-100">{document.title}</CardTitle>
        </div>

        <div className="flex items-center gap-3">
          {currentVersion && <StatusBadge status={currentVersion.state} />}
        </div>
      </CardHeader>

      {/* Prominent Restricted State Warning Box */}
      {isRestricted && (
        <div
          className="mb-5 p-4.5 bg-red-950/90 border-2 border-red-500 text-red-100 rounded-xl text-xs sm:text-sm leading-relaxed flex items-start gap-3 shadow-xl shadow-red-950/80"
          role="alert"
        >
          <span className="text-red-400 font-bold text-xl select-none" aria-hidden="true">🔴</span>
          <div className="space-y-1">
            <div className="font-bold tracking-wide uppercase text-xs sm:text-sm text-red-200 flex items-center gap-2">
              <span>DOCUMENT RESTRICTED — INTEGRITY ANOMALY ENFORCED</span>
            </div>
            <div className="text-slate-200 text-xs sm:text-sm mt-0.5 font-sans leading-normal">
              Cryptographic verification detected a physical byte discrepancy or custody failure. This version is locked down: successor version uploads and custody transfers are strictly prohibited on the backend.
            </div>
          </div>
        </div>
      )}

      {/* Current Version File Metadata Grid */}
      {currentVersion ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-xs font-semibold block">
                Original Filename
              </span>
              <span className="font-semibold text-slate-100 truncate block mt-1 text-sm font-mono" title={currentVersion.original_filename}>
                {currentVersion.original_filename}
              </span>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-xs font-semibold block">
                Format / Type
              </span>
              <span className="font-semibold text-cyan-300 block mt-1 text-sm">
                {getMimeLabel(currentVersion.mime_type)}
              </span>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-xs font-semibold block">
                File Size
              </span>
              <span className="font-semibold text-slate-100 block mt-1 text-sm font-mono">
                {formatFileSize(currentVersion.size_bytes)}
              </span>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-xs font-semibold block">
                Ingestion Time
              </span>
              <span className="font-semibold text-slate-200 block mt-1 text-xs font-mono" title={currentVersion.created_at}>
                {formatDateTime(currentVersion.created_at)}
              </span>
            </div>
          </div>

          {/* Cryptographic SHA-256 Hash Display */}
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
            <HashCopyBadge hash={currentVersion.sha256_hash} label="Verified Persisted SHA-256 Digest" />
          </div>
        </div>
      ) : (
        <p className="text-sm text-slate-400 italic">No version registered yet in this document container.</p>
      )}

      {/* Action Bar: Successor Version & History Toggle */}
      <div className="mt-5 pt-4 border-t border-slate-800/90 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          {versionHistory.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowHistory((prev) => !prev)}
              className="text-cyan-400 hover:text-cyan-300 font-semibold"
            >
              {showHistory ? '▲ Hide Version History' : `▼ View Version History (${versionHistory.length})`}
            </Button>
          )}
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {onVerifyVersion && currentVersion && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onVerifyVersion(document, currentVersion)}
              title={`Verify integrity for Version V${currentVersion.version_number}`}
            >
              ✓ Verify V{currentVersion.version_number} Integrity
            </Button>
          )}

          {onSimulateTamper && currentVersion && (
            <Button
              variant="outline"
              size="sm"
              disabled={isRestricted}
              onClick={() => onSimulateTamper(document, currentVersion)}
              title={isRestricted ? 'Cannot tamper a restricted version' : `Simulate controlled tampering on Version V${currentVersion.version_number} (DEMO MODE)`}
              className="text-amber-300 border-amber-800/90 hover:bg-amber-950/60"
            >
              ⚠ Simulate Tampering
            </Button>
          )}

          {onRequestTransfer && currentVersion && (
            <Button
              variant="outline"
              size="sm"
              disabled={isRestricted}
              onClick={() => onRequestTransfer(document, currentVersion)}
              title={isRestricted ? 'Cannot request transfer for a restricted document version' : `Request transfer for Version V${currentVersion.version_number}`}
            >
              ⇄ Request Transfer (V{currentVersion.version_number})
            </Button>
          )}

          {onUploadSuccessor && (
            <Button
              variant={isRestricted ? 'danger' : 'primary'}
              size="sm"
              disabled={isRestricted || isUploadingSuccessor}
              onClick={() => onUploadSuccessor(document.id)}
              title={isRestricted ? 'Cannot upload successor version to a restricted document' : 'Upload next immutable version'}
            >
              + Upload Successor Version
            </Button>
          )}
        </div>
      </div>

      {/* Immutable Version History Section */}
      {showHistory && versionHistory.length > 0 && (
        <div className="mt-5 pt-4 border-t border-slate-800 space-y-3 animate-fade-in">
          <div className="flex items-center justify-between text-xs font-sans text-slate-400">
            <span className="uppercase tracking-wide font-bold text-slate-300">
              Immutable Version Ledger (Oldest to Newest)
            </span>
            <span className="font-mono">{versionHistory.length} Recorded Versions</span>
          </div>

          <div className="space-y-2.5">
            {versionHistory.map((ver) => {
              const verRestricted = ver.state === 'RESTRICTED';
              const isCurrent = ver.version_number === currentVersion?.version_number;
              return (
                <div
                  key={ver.id}
                  className={`p-4 rounded-xl border text-xs space-y-3 ${
                    isCurrent
                      ? 'bg-slate-950 border-cyan-800/70 ring-1 ring-cyan-800/40'
                      : 'bg-slate-950/60 border-slate-800'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2.5">
                    <div className="flex items-center gap-2.5">
                      <Badge variant={isCurrent ? 'info' : 'neutral'}>
                        V{ver.version_number}
                      </Badge>
                      <span className="text-slate-100 font-bold font-mono text-sm">{ver.original_filename}</span>
                      <span className="text-slate-400 font-mono text-xs">({formatFileSize(ver.size_bytes)})</span>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusBadge status={ver.state} />
                      <span className="text-slate-400 font-mono text-xs">{formatDateTime(ver.created_at)}</span>

                      {onVerifyVersion && (
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => onVerifyVersion(document, ver)}
                          title={`Verify integrity for version V${ver.version_number}`}
                          className="text-xs h-7 px-2.5"
                        >
                          Verify V{ver.version_number}
                        </Button>
                      )}

                      {onSimulateTamper && (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={verRestricted}
                          onClick={() => onSimulateTamper(document, ver)}
                          title={verRestricted ? 'Cannot tamper a restricted version' : `Simulate tampering for version V${ver.version_number}`}
                          className="text-xs h-7 px-2.5 text-amber-300 border-amber-800 hover:bg-amber-950"
                        >
                          Tamper V{ver.version_number}
                        </Button>
                      )}

                      {onRequestTransfer && (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={verRestricted}
                          onClick={() => onRequestTransfer(document, ver)}
                          title={verRestricted ? 'Cannot transfer restricted version' : `Transfer version V${ver.version_number}`}
                          className="text-xs h-7 px-2.5"
                        >
                          Transfer V{ver.version_number}
                        </Button>
                      )}
                    </div>
                  </div>

                  <div className="pt-1">
                    <HashCopyBadge hash={ver.sha256_hash} label={`V${ver.version_number} Digest`} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
};
