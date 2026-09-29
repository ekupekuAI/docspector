import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { RequireAuth } from './components/layout/RequireAuth';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { CasesPage } from './pages/CasesPage';
import { CaseDetailPage } from './pages/CaseDetailPage';
import { DocumentsPage } from './pages/DocumentsPage';
import { DocumentDetailPage } from './pages/DocumentDetailPage';
import { DocumentVersionPage } from './pages/DocumentVersionPage';
import { TransfersPage } from './pages/TransfersPage';
import { IntegrityPage } from './pages/IntegrityPage';
import { AuditPage } from './pages/AuditPage';
import { ReportsPage } from './pages/ReportsPage';
import { VerificationConsolePage } from './pages/VerificationConsolePage';
import { NotFoundPage } from './pages/NotFoundPage';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            {/* Unauthenticated Login Route */}
            <Route path="/login" element={<LoginPage />} />

            {/* Authenticated Application Shell Routes */}
            <Route element={<RequireAuth />}>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/cases" element={<CasesPage />} />
              <Route path="/cases/:caseId" element={<CaseDetailPage />} />
              <Route path="/documents" element={<DocumentsPage />} />
              <Route path="/documents/:documentId" element={<DocumentDetailPage />} />
              <Route
                path="/documents/:documentId/versions/:versionId"
                element={<DocumentVersionPage />}
              />
              <Route path="/transfers" element={<TransfersPage />} />
              <Route path="/integrity" element={<IntegrityPage />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/verify" element={<VerificationConsolePage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
};

export default App;
