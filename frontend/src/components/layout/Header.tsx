import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export const Header: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const getRoleVariant = (role?: string) => {
    switch (role) {
      case 'SO':
        return 'danger';
      case 'IO':
        return 'info';
      case 'Legal Reviewer':
        return 'warning';
      case 'Auditor':
        return 'neutral';
      default:
        return 'neutral';
    }
  };

  return (
    <header className="h-16 bg-slate-950/95 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between select-none z-10 shrink-0">
      {/* Title / Context info */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 hidden sm:inline-block" />
          <h2 className="text-xs uppercase font-sans tracking-wide text-slate-300 font-semibold truncate">
            Electronic Evidence & Custody Command Console
          </h2>
        </div>
      </div>

      {/* User / Session management */}
      <div className="flex items-center gap-3">
        {isAuthenticated && user ? (
          <div className="flex items-center gap-3 bg-slate-900 border border-slate-700/80 px-3.5 py-1.5 rounded-xl shadow-sm">
            <div className="flex flex-col text-right">
              <span className="text-sm font-bold text-slate-100">{user.display_name}</span>
              <span className="text-xs font-mono text-cyan-400">@{user.username}</span>
            </div>
            <Badge variant={getRoleVariant(user.role)}>
              {user.role}
            </Badge>
            <div className="h-5 w-px bg-slate-700 mx-1" />
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                logout();
                navigate('/login');
              }}
              title="Sign Out of Session"
              className="text-xs px-2.5 py-1 text-slate-400 hover:text-slate-100"
            >
              Sign Out
            </Button>
          </div>
        ) : (
          <div className="flex items-center gap-3">
            <span className="text-xs text-amber-300 font-mono hidden sm:inline-block">Unauthenticated Session</span>
            <Button variant="primary" size="sm" onClick={() => navigate('/login')}>
              Sign In
            </Button>
          </div>
        )}
      </div>
    </header>
  );
};
