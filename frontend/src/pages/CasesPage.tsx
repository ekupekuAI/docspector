import React, { useEffect, useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { CaseRecord } from '../types';
import { CaseCard } from '../components/ui/CaseCard';
import { EmptyState } from '../components/ui/EmptyState';

export const CasesPage: React.FC = () => {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCases = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getCases();
      setCases(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch assigned cases.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      const matchesSearch =
        c.title.toLowerCase().includes(search.toLowerCase()) ||
        c.case_number.toLowerCase().includes(search.toLowerCase());
      const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [cases, search, statusFilter]);

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* Header & Filter Controls */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 font-sans">
            Case registry
          </p>
          <h1 className="mt-1 text-3xl font-bold text-slate-900 font-sans">Case Overview</h1>
        </div>

        <div className="flex flex-col gap-3 md:flex-row">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search cases"
              className="w-full rounded-xl border border-slate-200 bg-white pl-10 pr-4 py-2.5 text-sm text-slate-700 md:w-64 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-700 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
          >
            <option value="ALL">All statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="CLOSED">CLOSED</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Case Grid */}
      {isLoading ? (
        <div className="p-12 text-center text-slate-500 text-sm animate-pulse">
          Loading assigned cases...
        </div>
      ) : filteredCases.length === 0 ? (
        <EmptyState
          title="No matching cases"
          description="Adjust filters or search terms to view case records."
        />
      ) : (
        <div className="grid gap-5 lg:grid-cols-2">
          {filteredCases.map((caseItem) => (
            <CaseCard key={caseItem.id} caseItem={caseItem} />
          ))}
        </div>
      )}
    </div>
  );
};
