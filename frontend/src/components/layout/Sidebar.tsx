import React from 'react';
import { NavLink } from 'react-router-dom';

interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

interface NavItem {
  to: string;
  label: string;
  icon: string;
}

interface NavGroupItem {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroupItem[] = [
  {
    title: 'WORKSPACE',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: '▦' },
      { to: '/cases', label: 'Cases', icon: '🗂' },
      { to: '/documents', label: 'Documents', icon: '📄' },
    ],
  },
  {
    title: 'CUSTODY & REVIEW',
    items: [
      { to: '/transfers', label: 'Transfers', icon: '⇄' },
      { to: '/audit', label: 'Audit Timeline', icon: '📑' },
    ],
  },
  {
    title: 'INTEGRITY',
    items: [
      { to: '/integrity', label: 'Integrity Alerts', icon: '⚠' },
      { to: '/verify', label: 'Verification Console', icon: '🛡' },
    ],
  },
  {
    title: 'REPORTING',
    items: [
      { to: '/reports', label: 'Technical Reports', icon: '📊' },
    ],
  },
];

export const Sidebar: React.FC<SidebarProps> = ({
  isCollapsed = false,
  onToggleCollapse,
}) => {
  return (
    <aside
      className={`bg-slate-950 border-r border-slate-800 flex flex-col transition-all duration-200 select-none z-20 shrink-0 ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
      aria-label="Main Navigation"
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center px-4 border-b border-slate-800 justify-between bg-slate-950">
        {!isCollapsed ? (
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded bg-cyan-400 shadow-sm shadow-cyan-400/50" />
              <span className="font-bold text-base tracking-wider uppercase text-slate-100 font-mono">
                Docspector
              </span>
            </div>
            <span className="text-xs text-slate-400 tracking-tight pl-4 font-sans font-medium">
              Inspect. Verify. Trust.
            </span>
          </div>
        ) : (
          <div className="mx-auto flex flex-col items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-cyan-400 shadow-sm shadow-cyan-400/50" />
            <span className="font-bold text-xs tracking-wider uppercase text-slate-100 font-mono">
              DS
            </span>
          </div>
        )}
        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            className="text-slate-400 hover:text-slate-200 text-xs p-1.5 rounded-lg hover:bg-slate-800 border border-slate-800 transition"
            aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isCollapsed ? '→' : '←'}
          </button>
        )}
      </div>

      {/* Grouped Navigation Links */}
      <nav className="flex-1 py-4 px-2 space-y-5 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="space-y-1">
            {!isCollapsed && (
              <h3 className="px-3 text-[11px] font-sans uppercase font-semibold tracking-wide text-slate-400 mb-1.5">
                {group.title}
              </h3>
            )}
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-colors duration-150 ease-in-out ${
                    isActive
                      ? 'bg-slate-900 text-cyan-300 font-bold border border-slate-700/80 border-l-4 border-l-cyan-400 shadow-sm'
                      : 'text-slate-400 hover:bg-slate-900/60 hover:text-slate-200 border border-transparent'
                  }`
                }
                title={isCollapsed ? item.label : undefined}
              >
                <span className="text-base shrink-0 w-5 text-center" aria-hidden="true">
                  {item.icon}
                </span>
                {!isCollapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Node Status Indicator */}
      <div className="p-3 border-t border-slate-800 bg-slate-950">
        {!isCollapsed ? (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 text-xs text-slate-400 flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shrink-0" />
            <div className="truncate">
              <div className="font-bold text-slate-200 text-xs font-mono">Air-Gapped Node</div>
              <div className="text-[11px] text-slate-400 font-sans">Local Integrity Store</div>
            </div>
          </div>
        ) : (
          <div className="flex justify-center py-2" title="Air-Gapped Node Active — Local Integrity Store">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          </div>
        )}
      </div>
    </aside>
  );
};
