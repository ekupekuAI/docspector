import React from 'react';
import { Link } from 'react-router-dom';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center font-sans">
      <h1 className="text-4xl font-bold tracking-tight text-slate-900 font-mono">404</h1>
      <p className="mt-2 text-lg font-semibold text-slate-800">Page not found</p>
      <p className="mt-1 text-sm text-slate-500">
        The page you are looking for does not exist in the navigation workspace.
      </p>
      <Link
        to="/dashboard"
        className="mt-6 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 transition"
      >
        Return to Dashboard
      </Link>
    </div>
  );
};
