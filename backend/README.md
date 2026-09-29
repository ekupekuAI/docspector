# Docspector Backend

Docspector backend service.

## Stack

- Python 3.10+
- FastAPI
- Pydantic v2
- Pydantic Settings
- SQLAlchemy 2.0
- Alembic
- SQLite
- PyJWT

## Database & Persistence

- **Engine**: SQLite (local prototype database).
- **ORM**: SQLAlchemy 2.0 declarative models.
- **Migrations**: Alembic is the schema migration authority.
- **Foreign Keys**: SQLite foreign-key enforcement is explicitly enabled (`PRAGMA foreign_keys=ON`).
- **Privacy & Storage**: Local database files (`*.db`, `*.sqlite`, `*.sqlite3`) are ignored by Git and never committed.
- **Schema Evolution**: All schema changes must go through Alembic migrations.

### Core Tables

1. `users` — User identities and roles.
2. `cases` — Investigation/legal cases.
3. `case_assignments` — User-to-case access mappings.
4. `documents` — Logical document entities.
5. `document_versions` — Exact immutable version records.
6. `transfers` — Document version transfer requests and approvals.
7. `custody_events` — Ordered custody audit events.
8. `integrity_alerts` — Storage and integrity issue records.

## Demo Seed Data

Docspector provides an explicit, idempotent script to seed the database with synthetic demo data.

To seed the database:

```powershell
cd backend
python scripts/seed_demo.py
```

The script creates:
- **Four synthetic role-bearing users**:
  - `docspector.io` (`IO` — Investigation Officer)
  - `docspector.so` (`SO` — Supervising Officer)
  - `docspector.legal` (`Legal Reviewer` — Legal Reviewer)
  - `docspector.auditor` (`Auditor` — Audit Officer)
- **One fictional demo case**: `HYD-CYB-2026-0147` (Synthetic Cyber Evidence Review).
- **Four case assignments**: connecting all four synthetic users to the fictional case.

> **Important**: All seed data is synthetic and fictional for demonstration/development purposes only. It contains no real-world investigative, police, victim, or court records.

## Mock Authentication

Docspector currently uses synthetic mock JWT authentication for the hackathon prototype.

- Login uses a seeded synthetic username (no passwords are used).
- JWTs are signed with the configured development secret (`JWT_SECRET_KEY`).
- Tokens include subject (`sub`), `username`, `role`, `iat`, and `exp` claims.
- This is a prototype authentication mechanism and does not represent production/institutional identity management.

### Authentication Endpoints

- `POST /api/v1/auth/login` — Generate access token for a synthetic user.
  - Request body: `{"username": "docspector.io"}`
  - Response: `{"access_token": "<jwt>", "token_type": "bearer", "expires_in": 3600}`
- `GET /api/v1/auth/me` — Return identity of currently authenticated user.
  - Header: `Authorization: Bearer <token>`

## Configuration

Environment variables (with defaults):

- `APP_NAME` (default: `Docspector`)
- `APP_VERSION` (default: `0.1.0`)
- `APP_ENV` (default: `development`)
- `API_V1_PREFIX` (default: `/api/v1`)
- `DATABASE_URL` (default: `sqlite:///./docspector.db`)
- `JWT_SECRET_KEY` (default: `docspector-development-only-secret-change-me`)
- `JWT_ALGORITHM` (default: `HS256`)
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (default: `60`)

Copy `.env.example` to `.env` to override configuration locally.

## Development

Create and activate the virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run database migrations:

```powershell
alembic upgrade head
```

Rollback migrations:

```powershell
alembic downgrade -1
```

Start the development server:

```powershell
uvicorn app.main:app --reload
```

The backend will be available at `http://127.0.0.1:8000`.

## Endpoints

- `GET /` — Root endpoint returning application metadata and environment status.
- `GET /health` — Liveness and health endpoint returning service health status.
- `POST /api/v1/auth/login` — Mock login endpoint.
- `GET /api/v1/auth/me` — Authenticated identity endpoint.
- `GET /docs` — Swagger UI API documentation.

## Testing

Run tests with pytest:

```powershell
pytest
```
