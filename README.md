# Docspector

## Inspect. Verify. Trust.

Docspector is an application-level **tamper-evident document versioning and custody-assurance platform** for synthetic legal and investigation workflows.

> **Smart India Hackathon** — Problem Statement **SIH26190 (MHA)** · Theme: Blockchain & Cybersecurity · Local / intranet / air-gapped deployment · Synthetic data only.

---

## Quick start (no installation)

**Nothing to install — no Python, no Node, no zip extraction.**

1. Download the single-file app for your OS from [**Releases**](../../releases/latest):
   - `Docspector-windows-x64.exe` (Windows 10/11)
   - `Docspector-linux-x64` (Linux)
   - `Docspector-macos-arm64` (macOS, Apple Silicon)
2. Double-click it (on Linux/macOS: `chmod +x Docspector-* && ./Docspector-*`).
3. Your browser opens at `http://127.0.0.1:8000` with the demo case and four synthetic users already seeded.

| Demo login | Role |
|---|---|
| `docspector.io` | Investigation Officer |
| `docspector.so` | Supervising Officer |
| `docspector.legal` | Legal Reviewer |
| `docspector.auditor` | Audit Officer |

Everything runs locally on `127.0.0.1` — matching the PRD's local/air-gapped target. App data (SQLite database, file storage, generated JWT secret) lives in `%LOCALAPPDATA%\Docspector` (Windows) or `~/.local/share/docspector` (Linux/macOS).

> Windows SmartScreen may warn because the binary is unsigned — choose **More info → Run anyway**. On machines with **Smart App Control** enabled, run from source instead (below).

## What Docspector does

- Register synthetic case documents (PDF / PNG / TXT, ≤ 25 MB) with **SHA-256 integrity hashes**
- **Append-only immutable versioning** — prior versions are never overwritten
- **Version-scoped transfer approval** (IO requests → SO approves/rejects/revokes)
- **Per-case hash-chained custody ledger** with genesis anchoring and fork detection
- On-demand **file + chain integrity verification**; failures restrict the version and raise independent alerts
- **Tamper Injection Simulator** (explicit demo mode only) for live hash-mismatch demonstrations
- Custody timeline and Technical Integrity Report

## Important limitations

Docspector does **not**:

- Prove that a document is truthful or genuine.
- Prove that an uploader acted honestly.
- Determine legal admissibility.
- Provide absolute immutability.
- Protect against a fully privileged host or database administrator who can rewrite local files and records.

Docspector provides application-level tamper evidence under a defined trust model. Only synthetic fictional data may be used.

## Technology

| Layer | Stack |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Backend | Python 3.10+, FastAPI, Pydantic v2 |
| Persistence | SQLAlchemy 2.0, SQLite (FK enforced), Alembic migrations |
| Security | Mock JWT auth, case-based RBAC, object-level authorization, SHA-256 hash-chained custody events |
| Packaging | PyInstaller single-file executables via GitHub Actions (Windows / Linux / macOS) |

## Run from source (development)

Prerequisites: Python 3.10+ and Node.js 18+.

```bash
# 1. Backend
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt

# 2. Frontend
cd ../frontend
npm ci
```

**Option A — one process (packaged-style):** build the UI once, then let the backend serve it:

```bash
cd frontend && npm run build
cd ../backend && python desktop.py
```

**Option B — two dev servers (hot reload):**

```bash
# Terminal 1
cd backend
alembic upgrade head
python scripts/seed_demo.py
uvicorn app.main:app --reload          # http://127.0.0.1:8000

# Terminal 2
cd frontend
npm run dev                            # http://localhost:5173
```

## Build the executable yourself

```bash
python scripts/build_desktop.py        # output: backend/dist/Docspector(.exe)
```

Tagged releases (`v*`) automatically build all three platform binaries via [GitHub Actions](.github/workflows/release.yml) and attach them to the release.

## Tests

```bash
cd backend && pytest        # 372 tests: auth, RBAC, hash chain, tampering, concurrency, API contract
cd frontend && npm run build  # TypeScript strict typecheck + production build
```

## Documentation

- [Product Requirements Document](docs/Docspector_PRD.docx) (SIH26190 MVP)
- [Threat model](docs/THREAT_MODEL.md)
- [API error contract](docs/API_ERROR_CONTRACT.md)
- [Test traceability](docs/TRACEABILITY.md)
- [Demo limitations](docs/DEMO_LIMITATIONS.md)
- [Backend details](backend/README.md)

## License

See [LICENSE](LICENSE).
