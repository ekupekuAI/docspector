import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertTriangle, ArrowRight, FileText, UploadCloud } from 'lucide-react';
import { api } from '../api/client';
import { CaseRecord, CustodyEventItem, IntegrityAlertSummary, TransferRecord, DocumentBreakdownItem } from '../types';
import { MetricCard } from '../components/ui/MetricCard';
import { RoleSwitcher } from '../components/ui/RoleSwitcher';
import { StatusBadge } from '../components/status/StatusBadge';
import { useAuth } from '../context/AuthContext';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [activeCaseAlerts, setActiveCaseAlerts] = useState<IntegrityAlertSummary[]>([]);
  const [transfers] = useState<TransferRecord[]>([]);
  const [custodyEvents, setCustodyEvents] = useState<CustodyEventItem[]>([]);
  const [documents, setDocuments] = useState<DocumentBreakdownItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      const caseList = await api.getCases();
      setCases(caseList);

      if (caseList.length > 0) {
        const primaryCase = caseList[0];
        try {
          const [alertList, auditData, reportData] = await Promise.all([
            api.getCaseAlerts(primaryCase.id).catch(() => []),
            api.getCaseAudit(primaryCase.id).catch(() => null),
            api.getCaseReport(primaryCase.id).catch(() => null),
          ]);
          setActiveCaseAlerts(alertList);
          if (auditData?.events) {
            setCustodyEvents(auditData.events);
          }
          if (reportData?.document_breakdown) {
            setDocuments(reportData.document_breakdown);
          }
        } catch {
          // ignore single case fetch errors
        }
      }
    } catch {
      // ignore overall load error
    } finally {
      setIsLoading(false);
    }
  };

  const currentCase = cases[0];
  const restrictedCount = documents.filter((d) => d.latest_state === 'RESTRICTED').length;
  const openAlerts = activeCaseAlerts.filter((a) => a.status === 'OPEN');
  const pendingTransfers = transfers.filter((t) => t.status === 'PENDING');

  return (
    <div className="space-y-8 font-sans">
      {/* Header Banner */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 font-sans">
            Dashboard
          </h1>
          <p className="mt-1.5 text-base sm:text-lg text-slate-600 font-sans">
            Operational overview and case activity
          </p>
        </div>
        <RoleSwitcher />
      </div>

      {/* Top 4 Metrics Row */}
      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Total Assigned Cases"
          value={isLoading ? '...' : String(cases.length)}
          detail="Tracked across active casework"
        />
        <MetricCard
          label="Active Documents"
          value={isLoading ? '...' : String(documents.length)}
          detail={`${documents.length - restrictedCount} Verified • ${restrictedCount} Restricted`}
        />
        <MetricCard
          label="Pending Transfers"
          value={isLoading ? '...' : String(pendingTransfers.length).padStart(2, '0')}
          detail="Review queue status"
        />
        <MetricCard
          label="Integrity Alerts"
          value={isLoading ? '...' : String(openAlerts.length).padStart(2, '0')}
          detail="Open watchlist"
        />
      </div>

      {/* Operational Layout */}
      <div className="grid gap-6 xl:grid-cols-[1.5fr_0.9fr]">
        {/* Left Column: Active Primary Case */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-7 shadow-soft card-interactive">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <p className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">
                Active primary case
              </p>
              <h2 className="mt-1.5 text-2xl sm:text-3xl font-bold text-slate-900 font-mono">
                {currentCase ? currentCase.case_number : 'NO ASSIGNED CASE'}
              </h2>
            </div>
            {currentCase && <StatusBadge status={currentCase.status} />}
          </div>

          {currentCase ? (
            <div className="mt-5">
              <h3 className="text-xl sm:text-2xl font-bold text-slate-900 font-sans">{currentCase.title}</h3>
              <div className="mt-5 grid gap-5 md:grid-cols-2">
                <div>
                  <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Assigned Officer</div>
                  <div className="mt-1 text-base sm:text-lg font-medium text-slate-800 font-sans">{user?.display_name || 'Investigator'}</div>
                </div>
                <div>
                  <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Role Context</div>
                  <div className="mt-1 text-base sm:text-lg font-medium text-slate-800 font-sans">{user?.role || 'IO'}</div>
                </div>
                <div>
                  <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Status</div>
                  <div className="mt-1 text-base sm:text-lg font-medium text-slate-800 font-sans">{currentCase.status}</div>
                </div>
                <div>
                  <div className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">Secured Files</div>
                  <div className="mt-1 text-base sm:text-lg font-bold text-slate-900 font-mono">{documents.length}</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-5 text-base text-slate-500 italic font-sans">No case assigned to current session user.</div>
          )}

          <div className="mt-6 flex flex-wrap gap-4 pt-2">
            {currentCase && (
              <Link
                to={`/cases/${currentCase.id}`}
                className="inline-flex items-center gap-2.5 rounded-xl bg-blue-600 px-5 py-3 text-base font-semibold text-white hover:bg-blue-700 transition-colors duration-150 shadow-sm active:scale-[0.98]"
              >
                Open Case <ArrowRight className="h-5 w-5" />
              </Link>
            )}
            <Link
              to="/documents"
              className="inline-flex items-center gap-2.5 rounded-xl border border-slate-200 bg-white px-5 py-3 text-base font-semibold text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors duration-150 active:scale-[0.98]"
            >
              <FileText className="h-5 w-5" /> View documents
            </Link>
          </div>
        </div>

        {/* Right Column: Alerts & Transfer Highlights */}
        <div className="space-y-6">
          {/* Integrity Alert Card */}
          <div
            className={`rounded-2xl border p-6 shadow-soft card-interactive ${
              openAlerts.length > 0
                ? 'border-red-200 bg-red-50 text-red-900'
                : 'border-slate-200 bg-white text-slate-900'
            }`}
          >
            <div className="flex items-center gap-3.5">
              <div
                className={`rounded-full p-2.5 shrink-0 ${
                  openAlerts.length > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-600'
                }`}
              >
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <p
                  className={`text-sm font-semibold uppercase tracking-wide font-sans ${
                    openAlerts.length > 0 ? 'text-red-600' : 'text-slate-500'
                  }`}
                >
                  Integrity Watchlist
                </p>
                <h3 className="mt-1 font-bold text-lg sm:text-xl font-sans">
                  {openAlerts.length > 0
                    ? `${openAlerts.length} Open Integrity Alert(s)`
                    : 'All Evidence Hashes Valid'}
                </h3>
              </div>
            </div>
            {openAlerts.length > 0 ? (
              <div className="mt-4 text-sm space-y-1.5 font-sans">
                <div className="font-mono text-sm font-semibold">Alert ID: #{openAlerts[0].id}</div>
                <div className="text-slate-800 leading-relaxed">Message: {openAlerts[0].message}</div>
                <div className="mt-3">
                  <StatusBadge status="RESTRICTED" />
                </div>
              </div>
            ) : (
              <p className="mt-3.5 text-sm sm:text-base text-slate-600 font-sans leading-relaxed">
                No active physical hash mismatches or custody chain breakages detected.
              </p>
            )}
          </div>

          {/* Pending Transfer Card */}
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-6 shadow-soft card-interactive">
            <div className="flex items-center gap-3.5">
              <div className="rounded-full bg-amber-100 p-2.5 text-amber-700 shrink-0">
                <UploadCloud className="h-6 w-6" />
              </div>
              <div>
                <p className="text-sm font-semibold uppercase tracking-wide text-amber-700 font-sans">
                  Transfer Status
                </p>
                <h3 className="mt-1 font-bold text-lg sm:text-xl text-amber-950 font-sans">
                  {pendingTransfers.length > 0
                    ? `${pendingTransfers.length} Pending Transfer Request(s)`
                    : 'No Pending Transfers'}
                </h3>
              </div>
            </div>
            <p className="mt-3.5 text-sm sm:text-base text-amber-800 font-sans leading-relaxed">
              Transfers require Supervisory Officer approval before version access is unlocked for recipient.
            </p>
          </div>
        </div>
      </div>

      {/* Bottom Section: Recent Custody Activity */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-7 shadow-soft">
        <div className="mb-5 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-slate-500 font-sans">
              Recent custody activity
            </p>
            <h2 className="mt-1.5 text-xl sm:text-2xl font-bold text-slate-900 font-sans">Recent Custody Events</h2>
          </div>
          <button
            onClick={() => navigate('/audit')}
            className="text-sm sm:text-base font-semibold text-blue-600 hover:text-blue-700 transition-colors duration-150 font-sans"
          >
            View Full Audit Ledger →
          </button>
        </div>

        {custodyEvents.length === 0 ? (
          <div className="text-base text-slate-500 italic py-4 font-sans">No recent custody events logged.</div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {custodyEvents.slice(0, 6).map((evt) => (
              <div key={evt.id} className="rounded-xl border border-slate-200 bg-slate-50 p-4 sm:p-5 card-interactive">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-bold text-slate-900 font-sans text-sm sm:text-base">
                    {evt.event_type}
                  </span>
                  <span className="rounded-full bg-slate-100 px-3 py-1 text-xs sm:text-sm font-semibold text-slate-700 border border-slate-200 font-mono">
                    SEQ #{evt.sequence_number || evt.id}
                  </span>
                </div>
                <div className="mt-3 text-sm text-slate-700 font-mono">Actor: User #{evt.actor_user_id}</div>
                <div className="mt-1 text-sm text-slate-600 font-mono">
                  Time: {new Date(evt.event_time || evt.created_at).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
