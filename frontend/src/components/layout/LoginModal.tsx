import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Button } from '../ui/Button';
import { Card, CardHeader, CardTitle } from '../ui/Card';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PRESET_USERS = [
  { username: 'docspector.io', role: 'IO', label: 'Investigating Officer', desc: 'Case evidence ingestion, versioning, transfers' },
  { username: 'docspector.so', role: 'SO', label: 'Supervising Officer', desc: 'Case oversight, transfer approval & decisions' },
  { username: 'docspector.legal', role: 'Legal Reviewer', label: 'Legal Reviewer', desc: 'Evidence integrity audit and review' },
  { username: 'docspector.auditor', role: 'Auditor', label: 'Forensic Auditor', desc: 'Independent cryptographic verification' },
];

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const { login, isLoading, error } = useAuth();
  const [usernameInput, setUsernameInput] = useState('');
  const [activeError, setActiveError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLogin = async (username: string) => {
    setActiveError(null);
    try {
      await login(username);
      onClose();
    } catch (err: unknown) {
      setActiveError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-modal-backdrop">
      <Card className="w-full max-w-lg bg-slate-900 border-2 border-slate-700 shadow-2xl p-6 sm:p-7 space-y-4 animate-modal-content">
        <CardHeader className="border-b border-slate-800 pb-4 mb-2">
          <div>
            <span className="text-xs font-sans font-semibold tracking-wide uppercase text-cyan-400">
              Platform Authentication
            </span>
            <CardTitle className="text-xl font-bold mt-1">Air-Gapped Session Access</CardTitle>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-sm font-mono h-7 w-7 flex items-center justify-center rounded-lg hover:bg-slate-800 transition"
          >
            ✕
          </button>
        </CardHeader>

        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
          Docspector enforces strict server-authoritative role access boundaries. Select a registered officer profile below or authenticate with a custom username.
        </p>

        {(activeError || error) && (
          <div className="p-3.5 bg-rose-950/70 border border-rose-800 text-rose-200 text-xs rounded-lg">
            {activeError || error}
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold font-mono text-slate-300 mb-2 uppercase">
              Select Officer Profile:
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {PRESET_USERS.map((u) => (
                <button
                  key={u.username}
                  type="button"
                  onClick={() => handleLogin(u.username)}
                  disabled={isLoading}
                  className="flex flex-col text-left p-3.5 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800 hover:border-slate-600 transition text-xs space-y-1 group"
                >
                  <div className="flex items-center justify-between w-full">
                    <span className="font-bold text-slate-100 text-sm group-hover:text-cyan-300 transition-colors">
                      {u.role}
                    </span>
                    <span className="text-xs font-mono text-slate-400">@{u.username}</span>
                  </div>
                  <div className="text-slate-300 text-xs font-semibold">{u.label}</div>
                  <div className="text-[11px] text-slate-400 font-sans leading-tight pt-0.5">{u.desc}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="relative my-4">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-800" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-slate-900 px-3 text-slate-400 font-mono text-xs font-semibold">
                Or authenticate by username
              </span>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (usernameInput.trim()) {
                handleLogin(usernameInput.trim());
              }
            }}
            className="space-y-3.5"
          >
            <div>
              <input
                type="text"
                value={usernameInput}
                onChange={(e) => setUsernameInput(e.target.value)}
                placeholder="e.g. docspector.io"
                disabled={isLoading}
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>
            <Button
              type="submit"
              variant="primary"
              size="md"
              className="w-full text-sm py-2.5 font-bold"
              isLoading={isLoading}
              disabled={!usernameInput.trim()}
            >
              Sign In to Assigned Cases
            </Button>
          </form>
        </div>
      </Card>
    </div>
  );
};
