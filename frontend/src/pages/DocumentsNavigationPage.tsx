import React from 'react';
import { Card, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

interface DocumentsNavigationPageProps {
  onNavigateToCases: () => void;
  onNavigateHome: () => void;
}

export const DocumentsNavigationPage: React.FC<DocumentsNavigationPageProps> = ({
  onNavigateToCases,
  onNavigateHome,
}) => {
  return (
    <div className="space-y-10 animate-fade-in max-w-6xl mx-auto pb-16">
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-slate-800 gap-4">
        <div>
          <span className="text-xs font-mono font-bold tracking-widest uppercase text-cyan-400">
            Evidence Records & Custody Scoping
          </span>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100 mt-1">
            Document Ingestion & Version History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Documents and evidence files in Docspector are strictly scoped within assigned investigation cases.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="font-mono text-xs px-3 py-1.5 bg-slate-900 border border-slate-800 text-slate-300 font-bold rounded-lg">
            Case-Scoped Ingestion Policy
          </span>
        </div>
      </div>

      <Card className="p-7 sm:p-8 bg-slate-900 border-slate-800 space-y-5">
        <CardHeader className="pb-4 border-b border-slate-800">
          <div>
            <span className="text-xs font-mono tracking-widest text-cyan-400 uppercase font-bold">
              Operational Workflow Guide
            </span>
            <CardTitle className="text-xl font-bold mt-1">Ingesting and Managing Evidence Documents</CardTitle>
          </div>
        </CardHeader>

        <div className="space-y-4 text-sm text-slate-300 leading-relaxed font-sans">
          <p>
            In Docspector, every piece of evidence and subsequent version is cryptographically tied to an official case container. To maintain chain-of-custody compliance:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">1. Assigned Case File</span>
              <p className="text-xs text-slate-300 leading-relaxed">
                Open any case assigned to your authenticated officer profile (IO or SO). Case boundaries strictly prevent unauthorized cross-contamination.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">2. V1 Ingestion Subsystem</span>
              <p className="text-xs text-slate-300 leading-relaxed">
                Stream initial PDF, PNG, or TXT documents up to 25 MiB. Magic bytes are validated and SHA-256 digests are computed on-disk immediately.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">3. Immutable Successor Versions</span>
              <p className="text-xs text-slate-300 leading-relaxed">
                Commit sequential successor versions (V2, V3). Previous versions remain permanently preserved in the immutable custody chain ledger.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">4. Verification & Audit</span>
              <p className="text-xs text-slate-300 leading-relaxed">
                Execute dual-factor cryptographic verification or request version-scoped custody delegations to other verified investigators.
              </p>
            </div>
          </div>
        </div>

        <div className="pt-6 border-t border-slate-800 flex items-center justify-between flex-wrap gap-4">
          <Button variant="ghost" size="sm" onClick={onNavigateHome} className="text-slate-400 hover:text-slate-200">
            ← Return to Command Overview
          </Button>
          <Button variant="primary" size="md" onClick={onNavigateToCases} className="font-bold">
            Open Assigned Cases →
          </Button>
        </div>
      </Card>
    </div>
  );
};
