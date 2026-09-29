import React from 'react';
import { CustodyEventItem } from '../../types';

interface CustodyTimelineProps {
  events: CustodyEventItem[];
}

export const CustodyTimeline: React.FC<CustodyTimelineProps> = ({ events }) => {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-soft">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">Custody Timeline</p>
          <h3 className="mt-2 text-xl font-bold text-slate-900 font-sans">Event Chain</h3>
        </div>
      </div>

      {events.length === 0 ? (
        <div className="text-slate-500 text-sm italic font-sans py-4">No custody events recorded.</div>
      ) : (
        <div className="relative space-y-6 before:absolute before:left-4 before:top-1 before:h-[calc(100%-8px)] before:w-px before:bg-slate-200">
          {events.map((event, index) => (
            <div
              key={event.id}
              className="relative pl-10 animate-timeline-item"
              style={{ animationDelay: `${index * 60}ms` }}
            >
              <div className="absolute left-0 top-1.5 h-8 w-8 rounded-full bg-blue-100 text-center text-[10px] font-bold text-blue-700 ring-4 ring-white flex items-center justify-center font-sans">
                {event.event_type.slice(0, 2)}
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 font-sans card-interactive">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-slate-800 font-sans">
                    {event.event_type}
                  </div>
                  <span className="rounded-full bg-slate-100 border border-slate-200 px-2.5 py-0.5 text-xs font-semibold text-slate-700 font-mono">
                    SEQ #{event.sequence_number || event.id}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div className="font-mono text-slate-700">Actor ID: User #{event.actor_user_id}</div>
                  <div className="font-mono text-slate-500">Timestamp: {new Date(event.event_time || event.created_at).toLocaleString()}</div>
                  <div className="font-mono text-slate-500 truncate">Event SHA-256 Digest: {event.event_hash}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
