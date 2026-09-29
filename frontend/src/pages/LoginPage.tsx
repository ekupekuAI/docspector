import React, { FormEvent, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { demoUsers } from '../data/demoUsers';

export const LoginPage: React.FC = () => {
  const { isAuthenticated, login } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  const [selectedUsername, setSelectedUsername] = useState<string>('docspector.io');
  const [customUsername, setCustomUsername] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const targetUser = customUsername.trim() || selectedUsername;
    if (!targetUser) return;

    setIsSubmitting(true);
    setError('');

    try {
      await login(targetUser);
      showToast({
        type: 'success',
        title: 'Authentication Successful',
        message: `Signed in as ${targetUser}`,
      });
      navigate('/dashboard', { replace: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Authentication failed';
      setError(msg);
      showToast({
        type: 'error',
        title: 'Login Error',
        message: msg,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-100 px-4 py-12 text-slate-900 font-sans">
      <section className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 shadow-soft">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-blue-400/40 bg-blue-500/10 text-blue-600">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <p className="text-lg font-bold tracking-wide">Docspector</p>
            <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-semibold">
              Inspect. Verify. Trust.
            </p>
          </div>
        </div>

        <h1 className="mt-8 text-2xl font-bold tracking-tight text-slate-900">Docspector Login</h1>
        <p className="mt-2 text-sm text-slate-600">
          Sign in with a synthetic demo account or custom username. Real JWT authentication is issued by backend API.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label htmlFor="demo-role" className="block text-sm font-medium text-slate-700 mb-1">
              Select Demo User Role
            </label>
            <select
              id="demo-role"
              value={selectedUsername}
              onChange={(e) => {
                setSelectedUsername(e.target.value);
                setCustomUsername('');
                setError('');
              }}
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            >
              {demoUsers.map((u) => (
                <option key={u.username} value={u.username}>
                  {u.name} — {u.displayRole}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="custom-username" className="block text-sm font-medium text-slate-700 mb-1">
              Or Custom Username
            </label>
            <input
              id="custom-username"
              type="text"
              placeholder="e.g. investigator, supervisor..."
              value={customUsername}
              onChange={(e) => {
                setCustomUsername(e.target.value);
                setError('');
              }}
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            />
          </div>

          {error && <p role="alert" className="text-sm text-red-600 font-medium">{error}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 transition disabled:opacity-50"
          >
            {isSubmitting ? 'Authenticating...' : 'Login to Workstation'}
          </button>
        </form>
      </section>
    </main>
  );
};
