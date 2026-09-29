/**
 * Docspector Authentication Context (Milestone 21)
 * Inspect. Verify. Trust.
 * 
 * Provides centralized session management for mock JWT authentication.
 * Server remains authoritative for roles and case assignments.
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import { api } from '../api/client';
import { UserIdentity } from '../types';

interface AuthContextType {
  user: UserIdentity | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string) => Promise<void>;
  logout: () => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserIdentity | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const initializeAuth = async () => {
      const token = api.getToken();
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const currentUser = await api.getCurrentUser();
        setUser(currentUser);
      } catch (err) {
        // Stale or invalid token
        api.clearToken();
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const login = async (username: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await api.login(username);
      const currentUser = await api.getCurrentUser();
      setUser(currentUser);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Authentication failed.';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    api.clearToken();
    setUser(null);
    setError(null);
  };

  const clearError = () => setError(null);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        error,
        login,
        logout,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
