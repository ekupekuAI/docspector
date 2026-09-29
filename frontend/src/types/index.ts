/**
 * Docspector Core Types (Phase 4 Productization)
 * Inspect. Verify. Trust.
 * 
 * Strict alignment with backend Pydantic schemas and PRD models.
 */

// User and Auth Types
export type UserRole = 'IO' | 'SO' | 'Legal Reviewer' | 'Auditor';

export interface UserIdentity {
  id: number;
  username: string;
  display_name: string;
  role: UserRole;
  is_active: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// Error Contract Types (matching backend build_error_payload)
export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  request_id?: string;
}

export interface ApiErrorResponse {
  error: ApiErrorDetail;
  detail?: string;
}

// Case Types
export type CaseStatus = 'OPEN' | 'CLOSED' | string;

export interface CaseRecord {
  id: number;
  case_number: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  created_at: string;
}

export type CaseSummary = CaseRecord;
export type CaseResponse = CaseRecord;

// Document and Version States
export type DocumentVersionState = 'UPLOADING' | 'STORED' | 'RESTRICTED' | 'QUARANTINED' | string;
export type DocumentVersionStatus = DocumentVersionState;

export interface DocumentVersionRecord {
  id: number;
  document_id: number;
  version_number: number;
  state: DocumentVersionState;
  original_filename: string;
  mime_type: string;
  size_bytes: number;
  sha256_hash: string;
  created_by_user_id: number;
  created_at: string;
}

export type DocumentVersionSummary = DocumentVersionRecord;

export interface DocumentRecord {
  id: number;
  case_id: number;
  document_number: string;
  title: string;
  created_by_user_id: number;
  created_at: string;
  current_version?: DocumentVersionRecord | null;
}

export type DocumentSummary = DocumentRecord;
export type DocumentResponse = DocumentRecord;

export interface DocumentRegistrationResponse {
  document: DocumentRecord;
  version: DocumentVersionRecord;
}

// Transfer States
export type TransferStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'REVOKED' | string;

export interface TransferCreateRequest {
  recipient_user_id: number;
}

export interface TransferRecord {
  id: number;
  document_version_id: number;
  document_id: number;
  case_id: number;
  requester_user_id: number;
  recipient_user_id: number;
  status: TransferStatus;
  requested_at: string;
  decided_at?: string | null;
  decided_by_user_id?: number | null;
  revoked_at?: string | null;
}

export type TransferResponse = TransferRecord;
export type TransferSummary = TransferRecord;

// Integrity & Verification States
export type IntegrityOutcome = 'VALID' | 'INTEGRITY_FAILURE' | 'FILE_HASH_MISMATCH' | 'FILE_MISSING' | string;

export interface FileIntegrityDetail {
  is_valid: boolean;
  status: string;
  stored_hash: string;
  computed_hash?: string | null;
  expected_size_bytes: number;
  actual_size_bytes?: number | null;
  error_message?: string | null;
}

export interface ChainIntegrityDetail {
  is_valid: boolean;
  status: string;
  total_events: number;
  broken_sequence_number?: number | null;
  error_message?: string | null;
}

export interface IntegrityAlertSummary {
  id: number;
  case_id?: number;
  document_version_id?: number | null;
  document_id?: number;
  alert_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  status: string; // 'OPEN' | 'RESOLVED'
  message: string;
  description?: string;
  created_at: string;
  reviewed_at?: string | null;
  reviewed_by_user_id?: number | null;
  resolved_at?: string | null;
  resolved_by_id?: number | null;
  resolution_notes?: string | null;
}

export type IntegrityAlertResponse = IntegrityAlertSummary;

export interface VerificationResponse {
  document_id: number;
  document_version_id: number;
  version_number: number;
  case_id: number;
  overall_status: 'VALID' | 'INTEGRITY_FAILURE' | string;
  version_state: DocumentVersionState;
  file_integrity: FileIntegrityDetail;
  chain_integrity: ChainIntegrityDetail;
  alerts: IntegrityAlertSummary[];
}

export type VerificationResult = VerificationResponse;

// Custody Read API Types (Phase 2)
export interface CustodyEventItem {
  id: number;
  case_id: number;
  sequence_number: number;
  event_type: string;
  actor_user_id: number;
  event_time: string;
  document_version_id?: number | null;
  previous_event_hash?: string | null;
  event_hash: string;
  event_data?: Record<string, unknown> | string | null;
  created_at: string;
}

export interface DocumentCustodyResponse {
  document_id: number;
  case_id: number;
  document_number: string;
  events: CustodyEventItem[];
  chain_integrity: ChainIntegrityDetail;
}

export interface CaseAuditResponse {
  case_id: number;
  case_number: string;
  events: CustodyEventItem[];
  chain_integrity: ChainIntegrityDetail;
}

// Reports API Types (Phase 3)
export interface CaseReportInfo {
  id: number;
  case_number: string;
  title: string;
  description?: string | null;
  status: string;
  created_at: string;
}

export interface DocumentStateCounts {
  STORED: number;
  RESTRICTED: number;
  QUARANTINED: number;
  UPLOADING: number;
}

export interface DocumentReportSummary {
  total_documents: number;
  total_versions: number;
  by_state: DocumentStateCounts;
}

export interface IntegrityReportSummary {
  total_alerts: number;
  open_alerts: number;
  resolved_alerts: number;
  restricted_versions: number;
  custody_chain: ChainIntegrityDetail;
}

export interface TransferReportSummary {
  total: number;
  PENDING: number;
  APPROVED: number;
  REJECTED: number;
  REVOKED: number;
}

export interface CustodyReportSummary {
  total_events: number;
  first_event_at?: string | null;
  latest_event_at?: string | null;
}

export interface DocumentBreakdownItem {
  document_id: number;
  document_number: string;
  title: string;
  version_count: number;
  latest_version_number?: number | null;
  latest_state: string;
  latest_sha256?: string | null;
  created_at: string;
  // Fallbacks for display
  current_state?: string;
  file_hash?: string;
}

export interface CaseReportResponse {
  case: CaseReportInfo;
  generated_at: string;
  report_scope: string;
  documents: DocumentReportSummary;
  integrity: IntegrityReportSummary;
  transfers: TransferReportSummary;
  custody: CustodyReportSummary;
  document_breakdown: DocumentBreakdownItem[];
  // Legacy aliases
  custody_chain_status?: string;
  integrity_summary?: IntegrityReportSummary;
  document_summary?: DocumentReportSummary;
  version_state_breakdown?: DocumentReportSummary;
  transfer_summary?: TransferReportSummary;
  custody_summary?: CustodyReportSummary;
}

// Demo Tamper Response
export interface DemoTamperResponse {
  simulation_type: string;
  demo_mode: boolean;
  document_id: number;
  document_version_id: number;
  version_number: number;
  persisted_expected_sha256: string;
  message: string;
  disclaimer: string;
}

// Navigation Item
export type NavGroup = 'WORKSPACE' | 'CUSTODY & REVIEW' | 'INTEGRITY' | 'REPORTING';

export type NavRoute =
  | 'dashboard'
  | 'cases'
  | 'documents'
  | 'transfers'
  | 'integrity'
  | 'audit'
  | 'reports'
  | 'verify'
  | 'alerts';
