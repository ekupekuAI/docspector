import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { demoUsers } from '../../data/demoUsers';

export const RoleSwitcher: React.FC = () => {
  const { user, login } = useAuth();

  if (!user) return null;

  return (
    <div className="flex items-center gap-2.5 bg-white border border-slate-200 rounded-xl px-4 py-2.5 shadow-soft text-sm">
      <span className="text-slate-600 font-semibold font-sans">Active Role:</span>
      <select
        value={user.username}
        onChange={(e) => login(e.target.value)}
        className="bg-transparent text-slate-900 font-bold focus:outline-none cursor-pointer text-sm sm:text-base font-sans"
      >
        {demoUsers.map((u) => (
          <option key={u.username} value={u.username}>
            {u.name} ({u.displayRole})
          </option>
        ))}
      </select>
    </div>
  );
};
