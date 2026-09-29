# Docspector Demonstration Scope & Limitations

**Platform Purpose:** Synthetic Document Custody & Tamper Evidence
**Scope Notice:** Air-gapped / intranet synthetic demonstrator. Contains zero real law enforcement, court, victim, or suspect data.

---

## 1. Explicit Platform Nonclaims

Docspector is designed to showcase application-level cryptographic integrity controls and state machine guarantees.

1. **Not a Judicial Authenticity Guarantee**: Docspector demonstrates that stored files on disk match their registered SHA-256 digests and that custody transfer events form an unbroken linear hash chain. It does not replace forensic examiner certifications or court affidavits.
2. **Not Absolute Physical/Host Immutability**: Operating system administrators with root/kernel privileges or direct physical access to SQLite storage can theoretically modify disk blocks outside the application process.
3. **No Web3 / Blockchain Dependencies**: Docspector implements an internal, high-performance **hash-chained custody ledger** using standard cryptographic SHA-256 primitives; it does not utilize public blockchains, proof-of-work, or smart contracts.
4. **Synthetic Data Exclusivity**: All default cases (e.g. `HYD-CYB-2026-0147`) and users (`docspector.io`, `docspector.so`, `docspector.legal`, `docspector.auditor`) are purely synthetic demonstration entities.

---

## 2. DEMO_MODE Controls & Safety Invariants

### 1. The Synthetic Tamper Simulator
The tamper simulation endpoint (`POST /api/v1/demo/documents/{doc_id}/versions/{ver_id}/tamper`) exists strictly to demonstrate the verification engine's ability to detect file-byte discrepancies.

### 2. Safety Guards
- **Disabled by Default**: `DEMO_MODE` defaults to `False` in application settings.
- **Production Hard Block**: If `APP_ENV=production`, the application validator raises an immediate startup error if `DEMO_MODE=True`.
- **Authorization Guard**: The tamper endpoint enforces authenticated case assignment and requires an officer role (`IO` or `SO`); it returns HTTP 403 Forbidden if invoked without proper permissions or outside demo mode.
- **Zero Auto-Repair**: Once a document version enters the `RESTRICTED` state following integrity verification failure, the system prohibits automatic restoration or silent database hash updates.
