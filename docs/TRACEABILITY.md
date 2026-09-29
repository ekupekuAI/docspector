# Docspector Requirement-to-Test Traceability Matrix

**Project:** Docspector — Inspect. Verify. Trust.
**Baseline Test Suite:** 353 passed automated pytest test cases + frontend type & integration validation.

---

## 1. Backend Milestone Traceability (M1 – M20)

| Milestone | Capability / Security Requirement | Implementation Modules | Test Suite |
|---|---|---|---|
| **M1–M4** | Project scaffolding, config, DB schema & demo seed | `app/core/config.py`, `app/db/models/` | `test_db_state_integrity.py` |
| **M5** | Authentication, JWT token lifecycle & role verification | `app/api/auth.py`, `app/core/security.py` | `test_auth_api.py` |
| **M6** | Case management & IDOR assignment boundary | `app/api/cases.py`, `app/db/models/case.py` | `test_case_management.py` |
| **M7–M9** | Streaming file validation, V1 ingestion & crash-safe move | `app/services/file_validation.py`, `app/services/document_registration.py` | `test_document_registration.py` |
| **M10** | Immutable successor version registration (V2, V3, ...) | `app/services/document_registration.py` | `test_document_registration.py` |
| **M11** | Hash-chained custody ledger & cryptographic event audit | `app/services/custody_service.py` | `test_custody_chain.py` |
| **M12** | Version-scoped custody transfer state machine | `app/services/transfer_service.py`, `app/api/transfers.py` | `test_transfers.py` |
| **M13** | Independent two-factor integrity verification engine | `app/services/verification_service.py`, `app/api/documents.py` | `test_verification.py` |
| **M14** | Controlled synthetic demo tamper service & API error contract | `app/services/demo_tamper_service.py`, `app/api/demo.py`, `app/core/errors.py` | `test_api_security_and_tamper.py` |
| **M15** | Authorization, privilege escalation & IDOR attack audit | `app/api/dependencies.py` | `test_authorization_attacks.py` |
| **M16** | Malicious input, magic bytes & MIME spoofing security audit | `app/services/file_validation.py` | `test_input_security.py` |
| **M17** | File storage, path traversal & upload size abuse audit | `app/services/file_validation.py` | `test_file_storage_security.py` |
| **M18** | Database state integrity, locking & transaction audit | `app/db/` | `test_db_state_integrity.py` |
| **M19** | Secrets, config & dependency security audit | `app/core/config.py` | `test_secrets_config_audit.py` |
| **M20** | HTTP security headers, CORS & rate limit abuse hardening | `app/core/security_headers.py`, `app/core/rate_limit.py`, `app/core/request_limits.py` | `test_security_headers_and_cors.py`, `test_api_hardening.py` |
| **M26** | Integrity alert management & mandatory re-verification resolution | `app/services/alert_service.py`, `app/api/alerts.py` | `test_alerts_api.py` |
| **M27** | Document custody history & case audit read-only APIs | `app/services/custody_service.py`, `app/api/custody.py` | `test_custody_api.py` |
| **M28** | Real case technical integrity report aggregation API | `app/services/report_service.py`, `app/api/reports.py` | `test_reports_api.py` |

---

## 2. Frontend Milestone Traceability (M21 – M25)

| Milestone | Frontend Requirement | Implementation Components | Verification Artifact |
|---|---|---|---|
| **M21** | Foundation shell, design system & API client | `AppShell.tsx`, `client.ts`, `types/index.ts` | `npm run build` |
| **M22** | Case management & assigned investigation files | `CasesPage.tsx`, `CaseDetailPage.tsx` | `npm run build` |
| **M23** | Evidence ingestion & immutable version history ledger | `DocumentRecordCard.tsx`, `CaseDetailPage.tsx` | `npm run build` |
| **M24** | Custody transfer workflow (request, approve, reject, revoke) | `TransferRequestModal.tsx`, `TransferRecordCard.tsx`, `TransfersPage.tsx` | `test_m24.ts` |
| **M25** | Two-factor integrity verification & demo tamper console | `IntegrityVerificationPanel.tsx`, `DemoTamperModal.tsx`, `VerificationConsolePage.tsx` | `test_m25.ts` |

---

## 3. Core Demonstration Flow Traceability

```
[Store V1 File] ──► [Verify Integrity: VALID / STORED]
       │
       ▼ (DEMO MODE=True)
[Simulate Controlled Tampering] ──► Modifies on-disk storage bytes; DB SHA-256 preserved
       │
       ▼
[Verify Integrity] ──► Recomputes disk hash ──► Detects FILE_HASH_MISMATCH
       │
       ▼
[State Progression] ──► RESTRICTED state + CRITICAL integrity alert
       │
       ▼
[Transfer Protection] ──► Custody transfers strictly blocked (HTTP 409)
```
