/**
 * Docspector Centralized API Client (Phase 4 Productization)
 * Inspect. Verify. Trust.
 * 
 * Cleanly separates HTTP transport, auth token lifecycle, and standard
 * error parsing from presentation components.
 */

import {
  ApiErrorResponse,
  CaseAuditResponse,
  CaseRecord,
  CaseReportResponse,
  DemoTamperResponse,
  DocumentCustodyResponse,
  DocumentRegistrationResponse,
  IntegrityAlertSummary,
  TokenResponse,
  TransferRecord,
  UserIdentity,
  VerificationResponse,
} from '../types';

export class ApiError extends Error {
  public code: string;
  public details: Record<string, unknown>;
  public requestId?: string;
  public status: number;

  constructor(status: number, errorData: ApiErrorResponse) {
    const message = errorData.error?.message || errorData.detail || 'An unexpected API error occurred.';
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = errorData.error?.code || 'UNKNOWN_ERROR';
    this.details = errorData.error?.details || {};
    this.requestId = errorData.error?.request_id;
  }
}

class ApiClient {
  private baseUrl: string;
  private tokenKey = 'docspector_auth_token';

  constructor() {
    this.baseUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) || 'http://127.0.0.1:8000/api/v1';
  }

  public getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  public setToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
  }

  public clearToken(): void {
    localStorage.removeItem(this.tokenKey);
  }

  private getHeaders(customHeaders: Record<string, string> = {}, isJson = true): Headers {
    const headers = new Headers();
    if (isJson) {
      headers.set('Content-Type', 'application/json');
    }
    headers.set('Accept', 'application/json');

    const token = this.getToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    Object.entries(customHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });

    return headers;
  }

  public async request<T>(endpoint: string, options: RequestInit = {}, isJson = true): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const headers = this.getHeaders((options.headers as Record<string, string>) || {}, isJson);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        let errorPayload: ApiErrorResponse;
        try {
          errorPayload = await response.json();
        } catch {
          errorPayload = {
            error: {
              code: 'HTTP_ERROR',
              message: `HTTP ${response.status}: ${response.statusText}`,
              details: {},
            },
          };
        }
        throw new ApiError(response.status, errorPayload);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return await response.json();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        throw err;
      }
      throw new ApiError(0, {
        error: {
          code: 'NETWORK_ERROR',
          message: err instanceof Error ? err.message : 'Network communication failed.',
        },
      });
    }
  }

  // HTTP Helper Methods
  public async get<T>(endpoint: string, headers: Record<string, string> = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', headers });
  }

  public async post<T>(endpoint: string, data?: unknown, headers: Record<string, string> = {}): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
      headers,
    });
  }

  public async postMultipart<T>(endpoint: string, formData: FormData): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        method: 'POST',
        body: formData,
      },
      false
    );
  }

  // Auth APIs
  public async login(username: string): Promise<TokenResponse> {
    const response = await this.post<TokenResponse>('/auth/login', { username });
    if (response.access_token) {
      this.setToken(response.access_token);
    }
    return response;
  }

  public async getCurrentUser(): Promise<UserIdentity> {
    return this.get<UserIdentity>('/auth/me');
  }

  // Case APIs
  public async getCases(): Promise<CaseRecord[]> {
    return this.get<CaseRecord[]>('/cases');
  }

  public async getCase(caseId: number | string): Promise<CaseRecord> {
    return this.get<CaseRecord>(`/cases/${caseId}`);
  }

  // Document Upload & Version APIs
  public async uploadDocument(
    caseId: number | string,
    file: File,
    title?: string
  ): Promise<DocumentRegistrationResponse> {
    const formData = new FormData();
    formData.append('file', file);
    if (title && title.trim()) {
      formData.append('title', title.trim());
    }
    return this.postMultipart<DocumentRegistrationResponse>(`/cases/${caseId}/documents`, formData);
  }

  public async uploadSuccessorVersion(
    documentId: number | string,
    file: File
  ): Promise<DocumentRegistrationResponse> {
    const formData = new FormData();
    formData.append('file', file);
    return this.postMultipart<DocumentRegistrationResponse>(`/documents/${documentId}/versions`, formData);
  }

  // Transfer APIs
  public async requestTransfer(
    documentId: number | string,
    versionId: number | string,
    recipientUserId: number
  ): Promise<TransferRecord> {
    return this.post<TransferRecord>(
      `/documents/${documentId}/versions/${versionId}/transfers`,
      { recipient_user_id: recipientUserId }
    );
  }

  public async approveTransfer(transferId: number | string): Promise<TransferRecord> {
    return this.post<TransferRecord>(`/transfers/${transferId}/approve`);
  }

  public async rejectTransfer(transferId: number | string): Promise<TransferRecord> {
    return this.post<TransferRecord>(`/transfers/${transferId}/reject`);
  }

  public async revokeTransfer(transferId: number | string): Promise<TransferRecord> {
    return this.post<TransferRecord>(`/transfers/${transferId}/revoke`);
  }

  public async getTransfer(transferId: number | string): Promise<TransferRecord> {
    return this.get<TransferRecord>(`/transfers/${transferId}`);
  }

  // Verification & Demo Tamper APIs
  public async verifyDocumentVersion(
    documentId: number | string,
    versionId: number | string
  ): Promise<VerificationResponse> {
    return this.post<VerificationResponse>(`/documents/${documentId}/versions/${versionId}/verify`);
  }

  public async simulateTamper(
    documentId: number | string,
    versionId: number | string
  ): Promise<DemoTamperResponse> {
    return this.post<DemoTamperResponse>(`/demo/documents/${documentId}/versions/${versionId}/tamper`);
  }

  // Phase 1: Alerts APIs
  public async getCaseAlerts(caseId: number | string, statusFilter?: string): Promise<IntegrityAlertSummary[]> {
    const query = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
    return this.get<IntegrityAlertSummary[]>(`/cases/${caseId}/alerts${query}`);
  }

  public async resolveAlert(alertId: number | string, resolutionNote: string): Promise<IntegrityAlertSummary> {
    return this.post<IntegrityAlertSummary>(`/alerts/${alertId}/resolve`, { resolution_note: resolutionNote });
  }

  // Phase 2: Custody Read APIs
  public async getDocumentCustody(documentId: number | string): Promise<DocumentCustodyResponse> {
    return this.get<DocumentCustodyResponse>(`/documents/${documentId}/custody`);
  }

  public async getCaseAudit(caseId: number | string): Promise<CaseAuditResponse> {
    return this.get<CaseAuditResponse>(`/cases/${caseId}/audit`);
  }

  // Phase 3: Reports API
  public async getCaseReport(caseId: number | string): Promise<CaseReportResponse> {
    return this.get<CaseReportResponse>(`/cases/${caseId}/report`);
  }

  public async checkHealth(): Promise<{ status: string; service: string; environment: string }> {
    const rootUrl = this.baseUrl.replace(/\/api\/v1\/?$/, '');
    const res = await fetch(`${rootUrl}/health`);
    if (!res.ok) {
      throw new Error(`Health check failed: ${res.statusText}`);
    }
    return res.json();
  }
}

export const api = new ApiClient();
