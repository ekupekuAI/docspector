import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ShieldCheck, UserCircle2, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { demoUsers } from '../../data/demoUsers';

const navItems = [
  { label: 'Dashboard', to: '/dashboard' },
  { label: 'Cases', to: '/cases' },
  { label: 'Documents', to: '/documents' },
  { label: 'Transfers', to: '/transfers' },
  { label: 'Integrity', to: '/integrity' },
  { label: 'Audit', to: '/audit' },
  { label: 'Reports', to: '/reports' },
  { label: 'Verify', to: '/verify' },
];

export const TopNavigation: React.FC = () => {
  const { user, login, logout } = useAuth();
  const navigate = useNavigate();

  const handleRoleChange = async (username: string) => {
    try {
      await login(username);
    } catch {
      // login error handled by AuthContext
    }
  };

  return (
    <header className="border-b border-slate-800 bg-[#0b132b] text-slate-100 min-h-[74px] flex items-center shadow-md select-none">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-6 px-6 sm:px-8 lg:px-10 py-2.5">
        {/* Brand - Left */}
        <div
          className="flex items-center gap-3.5 cursor-pointer group shrink-0"
          onClick={() => navigate('/dashboard')}
        >
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-blue-400/40 bg-blue-500/10 text-blue-400 shadow-sm transition-colors group-hover:border-blue-400/70">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <div className="text-[21px] font-bold tracking-tight text-white font-sans leading-none">
              Docspector
            </div>
            <div className="mt-1 text-xs uppercase tracking-wider text-slate-400 font-semibold font-sans leading-none">
              INSPECT. VERIFY. TRUST.
            </div>
          </div>
        </div>

        {/* Navigation Items - Center */}
        <nav className="hidden items-center gap-2 lg:flex">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `relative rounded-xl px-4 py-2 text-[15px] transition-all duration-150 font-sans ${
                  isActive
                    ? 'bg-blue-600 text-white font-semibold shadow-sm border-b-2 border-blue-300'
                    : 'text-slate-300 font-medium hover:bg-slate-800/80 hover:text-white'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* User Role Switcher & Actions - Right */}
        <div className="flex items-center gap-3 shrink-0">
          {user && (
            <select
              value={user.username}
              onChange={(e) => handleRoleChange(e.target.value)}
              aria-label="Select demo role"
              className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-100 outline-none focus:ring-2 focus:ring-blue-500 font-sans cursor-pointer hover:border-slate-600 transition"
            >
              {demoUsers.map((u) => (
                <option key={u.username} value={u.username}>
                  {u.name} — {u.displayRole}
                </option>
              ))}
            </select>
          )}

          {user && (
            <div className="hidden items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/90 px-3 py-2 text-sm font-medium xl:flex text-slate-200">
              <UserCircle2 className="h-4.5 w-4.5 text-blue-400" />
              <span>{user.display_name || user.username}</span>
              <span className="px-2 py-0.5 rounded-md bg-blue-950 text-blue-300 border border-blue-800 text-xs font-semibold uppercase">
                {user.role}
              </span>
            </div>
          )}

          <button
            onClick={() => {
              logout();
              navigate('/login', { replace: true });
            }}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 hover:text-white transition-colors duration-150 active:scale-[0.98]"
          >
            <LogOut className="h-4 w-4" />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
};
