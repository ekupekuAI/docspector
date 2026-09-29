import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { TopNavigation } from './TopNavigation';

export const AppShell: React.FC = () => {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900 antialiased font-sans">
      <TopNavigation />
      <main key={location.pathname} className="mx-auto max-w-7xl px-6 sm:px-8 lg:px-10 py-8 animate-page-entry">
        <Outlet />
      </main>
    </div>
  );
};
