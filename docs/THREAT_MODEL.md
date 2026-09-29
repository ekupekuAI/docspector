# Docspector Threat Model & Security Architecture

**Product:** Docspector — Inspect. Verify. Trust.
**Version:** 0.1.0 (Release Candidate)
**Security Boundary:** FastAPI Backend Authorization + Cryptographic Verification Layer

---

## 1. Executive Summary & Nonclaims

Docspector is a local/intranet/air-gapped synthetic document custody and tamper-evidence platform designed for internal and law enforcement investigation units.

### Fundamental Nonclaims
Docspector provides **application-level cryptographic tamper evidence** under its defined trust model. It explicitly does **NOT** claim:
1. **Absolute Immutability**: Underlying operating system storage and database administrator accounts can technically alter state outside the application runtime.
2. **Protection Against Host/DBA Compromise**: A fully privileged root administrator with direct raw disk access is outside the application threat model.
3. **Legal Admissibility**: Tamper evidence demonstrates byte match and ledger continuity; it does not replace judicial rules of evidence or forensic affidavits.
4. **Proof of Document Truthfulness or Original Authenticity**: Docspector verifies whether an ingested document version has remained unmodified since submission; it cannot judge author intent or factual accuracy.

---

## 2. Trust Model & System Boundaries

```
Client (Browser / React Frontend)
   │  [Untrusted Presentation Boundary - Zero Security Decisions]
   ▼  (Bearer JWT + Standard JSON Error Envelopes)
FastAPI Backend Application
   ├── Universal Error Sanitization & Request-ID Middleware
   ├── Rate Limiting & Input Validation Layer
   ├── JWT Authentication & Role-Based Access Control (IO, SO, Legal, Auditor)
   ├── IDOR Guard (Case Assignment Verification)
   ├── Custody Transfer State Machine
   ├── Two-Factor Verification Engine (File SHA-256 + Hash Chain Audit)
   └── Controlled DEMO_MODE Guard
         │
         ├── SQLite DB (State Machine & Ledger)
         └── Private Filesystem Storage (Atomic & Crash-Safe Keying)
```

---

## 3. Threat Classification & Mitigation Matrix

| Threat Category | Identified Attack Vector | Platform Countermeasure | Backend Test Reference |
|---|---|---|---|
| **Identity & Auth** | JWT forgery, `none` algorithm attacks, expired tokens | Symmetric HS256 validation with minimum key entropy enforcement; production rejection of weak dev keys | `test_auth_api.py`, `test_secrets_config_audit.py` |
| **Privilege Escalation** | IO invoking SO approval or demo tamper in production | Strict role checking (`check_user_role`) + `DEMO_MODE=False` production barrier | `test_authorization_attacks.py`, `test_api_hardening.py` |
| **IDOR / Tenant Leak** | Accessing case documents or transfers across unassigned cases | Mandatory `CaseAssignment` query scoping returning uniform 404 non-disclosure | `test_case_management.py`, `test_authorization_attacks.py` |
| **Data Tampering** | Silent alteration of on-disk file bytes | On-disk SHA-256 recomputation; automatic transition to `RESTRICTED` state + immutable critical alerts | `test_verification.py`, `test_file_storage_security.py` |
| **Ledger Manipulation** | Reordering, deleting, or injecting custody events | Monotonically increasing sequences + SHA-256 hash chaining back to `GENESIS` | `test_custody_chain.py`, `test_db_state_integrity.py` |
| **Race Conditions** | Concurrent transfer approvals or version registration collisions | Conditional state transitions returning HTTP 409 Conflict + SQLite transaction retries | `test_transfers.py`, `test_document_registration.py` |
| **File Upload Abuse** | Path traversal (`../../`), MIME spoofing, zip bombs, oversized files | Magic-byte header inspection, filename stripping, strict 25 MiB streaming limit, randomized UUID storage keys | `test_input_security.py`, `test_file_storage_security.py` |
| **API Abuse** | Oversized JSON payloads, credential brute-forcing | 1 MiB body limit middleware, in-process sliding window login rate limiter | `test_api_hardening.py`, `test_security_headers_and_cors.py` |

---

## 4. Production Security Gate Invariants

1. `DEMO_MODE` must default to `False`.
2. Server startup is **aborted** in `production` environment if `DEMO_MODE=True`.
3. Server startup is **aborted** in `production` environment if `jwt_secret_key` uses default dev secrets or is $< 32$ characters.
4. Wildcard CORS (`*`) with credentials enabled is **aborted** in `production`.
5. Frontend relies 100% on backend HTTP responses (401, 403, 404, 409, 422, 429, 500) as the sole security boundary.
