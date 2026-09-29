import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, ChevronDown, LogIn, LogOut, UserCircle2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { demoUsers } from '../../data/demoUsers';

/**
 * Compact account dropdown for the top navigation.
 * Shows the signed-in identity and offers: switch demo account,
 * open the login page for a different user, and logout.
 */
export const AccountMenu: React.FC = () => {
  const { user, login, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleEscape);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [open]);

  if (!user) return null;

  const handleSwitchAccount = async (username: string) => {
    setOpen(false);
    if (username === user.username) return;
    try {
      await login(username);
    } catch {
      // login error handled by AuthContext
    }
  };

  const handleLoginPage = () => {
    setOpen(false);
    logout();
    navigate('/login', { replace: true });
  };

  const handleLogout = () => {
    setOpen(false);
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <div ref={menuRef} className="relative">
      <button
        onClick={() => setOpen((prev) => !prev)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 hover:text-white transition-colors duration-150"
      >
        <UserCircle2 className="h-5 w-5 text-blue-400" />
        <span className="max-w-[9rem] truncate hidden md:inline">
          {user.display_name || user.username}
        </span>
        <span className="px-1.5 py-0.5 rounded-md bg-blue-950 text-blue-300 border border-blue-800 text-[11px] font-semibold uppercase">
          {user.role}
        </span>
        <ChevronDown
          className={`h-4 w-4 text-slate-400 transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-50 mt-2 w-72 rounded-xl border border-slate-700 bg-[#0b132b] shadow-xl shadow-black/40 overflow-hidden"
        >
          <div className="px-4 py-3 border-b border-slate-800">
            <div className="text-sm font-semibold text-white">
              {user.display_name || user.username}
            </div>
            <div className="mt-0.5 text-xs text-slate-400">
              {user.username} · {user.role}
            </div>
          </div>

          <div className="py-1.5">
            <div className="px-4 pb-1 pt-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Switch demo account
            </div>
            {demoUsers.map((demoUser) => {
              const isCurrent = demoUser.username === user.username;
              return (
                <button
                  key={demoUser.username}
                  role="menuitem"
                  onClick={() => handleSwitchAccount(demoUser.username)}
                  className={`flex w-full items-center justify-between gap-2 px-4 py-2 text-left text-sm transition-colors ${
                    isCurrent
                      ? 'text-blue-300 bg-blue-500/10'
                      : 'text-slate-200 hover:bg-slate-800/80 hover:text-white'
                  }`}
                >
                  <span>
                    <span className="block font-medium">{demoUser.name}</span>
                    <span className="block text-xs text-slate-400">{demoUser.displayRole}</span>
                  </span>
                  {isCurrent && <Check className="h-4 w-4 shrink-0" />}
                </button>
              );
            })}
          </div>

          <div className="border-t border-slate-800 py-1.5">
            <button
              role="menuitem"
              onClick={handleLoginPage}
              className="flex w-full items-center gap-2.5 px-4 py-2 text-left text-sm text-slate-200 hover:bg-slate-800/80 hover:text-white transition-colors"
            >
              <LogIn className="h-4 w-4 text-blue-400" />
              Login as different user…
            </button>
            <button
              role="menuitem"
              onClick={handleLogout}
              className="flex w-full items-center gap-2.5 px-4 py-2 text-left text-sm text-red-300 hover:bg-red-500/10 hover:text-red-200 transition-colors"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
