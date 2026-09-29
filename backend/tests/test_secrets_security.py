"""Docspector Milestone 19 - Secrets, Credentials, Configuration & Dependency Security Tests.

Inspect. Verify. Trust.

Comprehensive adversarial security test suite testing:
- Secret management & committed file audit (SECRETSEC-01)
- Production configuration security & secret validation (SECRETSEC-02)
- DEMO_MODE defaults to false (SECRETSEC-03)
- Secret non-exposure in API responses (SECRETSEC-04)
- Explicit JWT algorithm whitelist validation (SECRETSEC-05)
- Expired JWT token rejection (SECRETSEC-06)
- Tampered JWT token rejection (SECRETSEC-07)
- Role elevation via JWT manipulation prevented (SECRETSEC-08)
- Case assignment bypass via JWT prevented (SECRETSEC-09)
- Stack trace non-exposure in API errors (SECRETSEC-10)
- Database connection details non-exposure (SECRETSEC-11)
- Private filesystem storage path non-exposure (SECRETSEC-12)
- Safe header/credential logging practices (SECRETSEC-13)
- Demo mode safe defaults (SECRETSEC-14)
- Role & case scoping for demo tamper operations (SECRETSEC-15)
- Client-controlled storage path rejection (SECRETSEC-16)
- Client-controlled SHA-256 rejection (SECRETSEC-17)
- Environment config secret non-exposure (SECRETSEC-18)
- .gitignore patterns protection (SECRETSEC-19)
- Lockfile and dependency consistency (SECRETSEC-20)
- Demo mode attack scenarios (SECRETSEC-DEMO-01 to SECRETSEC-DEMO-06)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.security import create_access_token, decode_access_token
from app.db.base import Base
from app.db.models import (
    Case,
    CaseAssignment,
    CustodyEvent,
    Document,
    DocumentVersion,
    User,
)
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def secretsec_fixture(monkeypatch):
    """Set up an isolated testing environment with dedicated SQLite database and temporary storage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        temp_storage_path = temp_dir_path / "storage"
        temp_storage_path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))
        monkeypatch.setattr(settings, "demo_mode", False)

        db_file = temp_dir_path / "test_docspector_secretsec.db"
        db_url = f"sqlite:///{db_file}"

        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30},
            echo=False,
        )

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        session = TestingSessionLocal()
        seed_demo_data(session)
        session.commit()

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        doc_1, v1, _ = register_document_version_one(
            db=session,
            case=case_1,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="secretsec_evidence.pdf",
            content_type="application/pdf",
            storage_dir=temp_storage_path,
        )

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)

        yield {
            "client": client,
            "db": session,
            "storage_dir": temp_storage_path,
            "case": case_1,
            "doc": doc_1,
            "version": v1,
            "io_user": io_user,
            "so_user": so_user,
            "auditor_user": auditor_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
            "auditor_token": create_access_token(auditor_user),
        }

        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


# ===========================================================================
# SECRETSEC-01 to SECRETSEC-10
# ===========================================================================

def test_secretsec_01_no_committed_env_secret_file():
    """SECRETSEC-01: No committed .env file exists in repository root or backend."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    root_env = repo_root / ".env"
    backend_env = repo_root / "backend" / ".env"
    frontend_env = repo_root / "frontend" / ".env"

    assert not root_env.is_file(), "Found unignored .env in repository root!"
    assert not backend_env.is_file(), "Found unignored .env in backend directory!"
    assert not frontend_env.is_file(), "Found unignored .env in frontend directory!"

    # Verify .env.example files exist as templates
    assert (repo_root / "backend" / ".env.example").is_file()
    assert (repo_root / "frontend" / ".env.example").is_file()


def test_secretsec_02_production_configuration_rejects_insecure_jwt_secret():
    """SECRETSEC-02: Production environment rejects default, insecure, missing, or short JWT secret keys."""
    # Production with default dev secret -> rejected
    with pytest.raises(ValueError, match="Insecure default or short JWT secret key"):
        Settings(
            app_env="production",
            jwt_secret_key="docspector-development-only-secret-change-me",
            demo_mode=False,
            cors_allowed_origins=["https://app.docspector.example"],
        )

    # Production with empty/missing secret -> rejected
    with pytest.raises(ValueError, match="Insecure default or short JWT secret key"):
        Settings(
            app_env="production",
            jwt_secret_key="",
            demo_mode=False,
            cors_allowed_origins=["https://app.docspector.example"],
        )

    # Production with short secret (< 32 chars) -> rejected
    with pytest.raises(ValueError, match="Insecure default or short JWT secret key"):
        Settings(
            app_env="production",
            jwt_secret_key="short_secret_key_123",
            demo_mode=False,
            cors_allowed_origins=["https://app.docspector.example"],
        )

    # Production with strong secret (>= 32 chars), demo_mode=False, and explicit CORS origin -> accepted
    prod_settings = Settings(
        app_env="production",
        jwt_secret_key="production_super_secret_cryptographic_key_32_chars!",
        demo_mode=False,
        cors_allowed_origins=["https://app.docspector.example"],
    )
    assert prod_settings.app_env == "production"


def test_secretsec_production_cors_validation():
    """SECRETSEC-CORS: Production environment strictly validates CORS origins."""
    valid_jwt = "production_super_secret_cryptographic_key_32_chars!"

    # Production + wildcard "*" string -> rejected
    with pytest.raises(ValueError, match=r"Wildcard CORS origin '\*' is strictly prohibited"):
        Settings(
            app_env="production",
            jwt_secret_key=valid_jwt,
            demo_mode=False,
            cors_allowed_origins="*",
        )

    # Production + wildcard ["*"] list -> rejected
    with pytest.raises(ValueError, match=r"Wildcard CORS origin '\*' is strictly prohibited"):
        Settings(
            app_env="production",
            jwt_secret_key=valid_jwt,
            demo_mode=False,
            cors_allowed_origins=["*"],
        )

    # Production + empty origins list -> rejected
    with pytest.raises(ValueError, match=r"Wildcard CORS origin '\*' is strictly prohibited"):
        Settings(
            app_env="production",
            jwt_secret_key=valid_jwt,
            demo_mode=False,
            cors_allowed_origins=[],
        )

    # Production + single explicit origin -> accepted
    prod_single = Settings(
        app_env="production",
        jwt_secret_key=valid_jwt,
        demo_mode=False,
        cors_allowed_origins="https://app.docspector.example",
    )
    assert prod_single.cors_allowed_origins == ["https://app.docspector.example"]

    # Production + multiple explicit origins -> accepted
    prod_multi = Settings(
        app_env="production",
        jwt_secret_key=valid_jwt,
        demo_mode=False,
        cors_allowed_origins=["https://app.docspector.example", "https://admin.docspector.example"],
    )
    assert prod_multi.cors_allowed_origins == [
        "https://app.docspector.example",
        "https://admin.docspector.example",
    ]

    # Development/test + wildcard -> allowed (preserves existing dev workflow)
    dev_settings = Settings(
        app_env="development",
        cors_allowed_origins=["*"],
    )
    assert dev_settings.cors_allowed_origins == ["*"]


def test_secretsec_03_demo_mode_defaults_false():
    """SECRETSEC-03: DEMO_MODE strictly defaults to False in standard Settings."""
    fresh_settings = Settings()
    assert fresh_settings.demo_mode is False


def test_secretsec_04_jwt_secret_not_exposed_through_api(secretsec_fixture):
    """SECRETSEC-04: API responses (root, health, errors, cases) never leak the JWT secret."""
    client = secretsec_fixture["client"]

    endpoints = ["/", "/health", "/api/v1/cases"]
    for ep in endpoints:
        resp = client.get(ep)
        assert settings.jwt_secret_key not in resp.text
        assert "jwt_secret" not in resp.text.lower()


def test_secretsec_05_jwt_algorithm_explicitly_validated():
    """SECRETSEC-05: Insecure algorithms ('none', 'RS256' when HMAC expected, etc.) are rejected."""
    # Unsupported algorithm
    with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
        Settings(jwt_algorithm="none")

    with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
        Settings(jwt_algorithm="RS256")

    # Allowed HMAC algorithms
    s256 = Settings(jwt_algorithm="HS256")
    s384 = Settings(jwt_algorithm="HS384")
    s512 = Settings(jwt_algorithm="HS512")
    assert s256.jwt_algorithm == "HS256"
    assert s384.jwt_algorithm == "HS384"
    assert s512.jwt_algorithm == "HS512"


def test_secretsec_06_expired_jwt_rejected(secretsec_fixture):
    """SECRETSEC-06: Expired JWT tokens are rejected with authentication error."""
    client = secretsec_fixture["client"]
    user = secretsec_fixture["io_user"]

    expired_payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
    }
    expired_token = jwt.encode(expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    resp = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")
    assert "credentials" in resp.json()["error"]["message"].lower() or "token" in resp.json()["error"]["message"].lower()


def test_secretsec_07_tampered_jwt_rejected(secretsec_fixture):
    """SECRETSEC-07: Tampered JWT signature or payload is rejected with 401."""
    client = secretsec_fixture["client"]
    token = secretsec_fixture["io_token"]

    # Tamper with token signature
    tampered_token = token[:-5] + "XXXXX"

    resp = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == 401


def test_secretsec_08_jwt_cannot_elevate_role(secretsec_fixture):
    """SECRETSEC-08: Altering role in JWT payload does not bypass server-side DB role check."""
    client = secretsec_fixture["client"]
    user = secretsec_fixture["auditor_user"]  # Role: Auditor
    case = secretsec_fixture["case"]

    # Attacker crafts JWT with role="SO" but sub=auditor_user.id
    forged_payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": "SO",  # Forged elevation attempt
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    forged_token = jwt.encode(forged_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    # Attempt SO-only endpoint: upload document version
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("forged.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Forged Role Upload"},
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    # Server looks up user by sub in database and discovers true role is Auditor -> 403 Forbidden
    assert resp.status_code == 403


def test_secretsec_09_jwt_cannot_bypass_case_assignment(secretsec_fixture):
    """SECRETSEC-09: A valid JWT for an unassigned user cannot bypass server-side case assignment."""
    client = secretsec_fixture["client"]
    db = secretsec_fixture["db"]

    # Create unassigned user
    unassigned = User(
        username="unassigned_sec_user",
        display_name="Unassigned User",
        role="IO",
        is_active=True,
    )
    db.add(unassigned)
    db.commit()

    token = create_access_token(unassigned)
    case = secretsec_fixture["case"]

    resp = client.get(f"/api/v1/cases/{case.id}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404  # Non-assigned case returns 404


def test_secretsec_10_api_errors_do_not_expose_stack_traces(secretsec_fixture):
    """SECRETSEC-10: 4xx and 5xx API error responses conform to envelope and contain no stack traces."""
    client = secretsec_fixture["client"]

    # Malformed endpoint request
    resp = client.post(
        "/api/v1/cases/99999/documents",
        data={"invalid": "payload"},
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert resp.status_code in (401, 404, 422)
    resp_text = resp.text

    assert "Traceback (most recent call last)" not in resp_text
    assert "File \"" not in resp_text
    assert "line " not in resp_text.lower() or "validation_errors" in resp_text


# ===========================================================================
# SECRETSEC-11 to SECRETSEC-20
# ===========================================================================

def test_secretsec_11_api_errors_do_not_expose_database_connection_details(secretsec_fixture):
    """SECRETSEC-11: Database errors never leak raw database credentials or connection strings."""
    token = secretsec_fixture["io_token"]

    def mock_broken_get_db():
        raise RuntimeError("sqlite+pysqlite:///user:SECRET_PASS_999@localhost/db.sqlite")

    app.dependency_overrides[get_db] = mock_broken_get_db

    client_safe = TestClient(app, raise_server_exceptions=False)
    resp = client_safe.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 500
    assert "SECRET_PASS_999" not in resp.text
    assert "sqlite+pysqlite" not in resp.text

    app.dependency_overrides.clear()



def test_secretsec_12_api_errors_do_not_expose_private_storage_paths(secretsec_fixture):
    """SECRETSEC-12: API error responses never expose the server's private storage path."""
    client = secretsec_fixture["client"]
    case = secretsec_fixture["case"]
    token = secretsec_fixture["io_token"]

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("fake.pdf", b"INVALID_MAGIC_HEADER", "application/pdf")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert "storage/private" not in resp.text
    assert "C:\\" not in resp.text
    assert "/var/data" not in resp.text


def test_secretsec_13_authorization_headers_and_jwts_not_logged(secretsec_fixture, caplog):
    """SECRETSEC-13: Standard API requests do not log raw Authorization headers or JWT secrets."""
    caplog.clear()
    client = secretsec_fixture["client"]
    token = secretsec_fixture["io_token"]

    response = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    for record in caplog.records:
        assert token not in record.message
        assert settings.jwt_secret_key not in record.message


def test_secretsec_14_demo_mode_defaults_safely():
    """SECRETSEC-14: Fresh Settings and default environment has demo_mode set to False."""
    fresh_s = Settings(app_env="development")
    assert fresh_s.demo_mode is False

    with pytest.raises(ValueError, match="DEMO_MODE is strictly forbidden in production"):
        Settings(app_env="production", jwt_secret_key="a" * 32, demo_mode=True)


def test_secretsec_15_demo_tamper_remains_role_and_case_scoped(secretsec_fixture, monkeypatch):
    """SECRETSEC-15: Even when DEMO_MODE=true, tamper endpoint requires active case assignment and IO/SO role."""
    client = secretsec_fixture["client"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]
    auditor_token = secretsec_fixture["auditor_token"]

    monkeypatch.setattr(settings, "demo_mode", True)

    # Auditor role attempting tamper -> 403 Forbidden
    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp.status_code == 403


def test_secretsec_16_no_client_controlled_storage_path_accepted(secretsec_fixture):
    """SECRETSEC-16: Submitting client-controlled storage_key or storage_path is ignored / rejected."""
    client = secretsec_fixture["client"]
    case = secretsec_fixture["case"]
    token = secretsec_fixture["io_token"]
    db = secretsec_fixture["db"]

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("path_test.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Path Test", "storage_key": "/etc/passwd"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201

    created_ver = (
        db.query(DocumentVersion)
        .filter(DocumentVersion.document_id == resp.json()["document"]["id"])
        .first()
    )
    assert created_ver.storage_key != "/etc/passwd"
    assert created_ver.storage_key.endswith(".pdf")
    assert "/" not in created_ver.storage_key


def test_secretsec_17_no_client_controlled_sha256_overrides_server_hash(secretsec_fixture):
    """SECRETSEC-17: Client cannot supply a declared SHA-256 hash to override computed hash."""
    client = secretsec_fixture["client"]
    case = secretsec_fixture["case"]
    token = secretsec_fixture["io_token"]
    db = secretsec_fixture["db"]

    fake_hash = "deadbeef" * 8
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("hash_test.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Hash Test", "sha256": fake_hash},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201

    created_ver = (
        db.query(DocumentVersion)
        .filter(DocumentVersion.document_id == resp.json()["document"]["id"])
        .first()
    )
    expected_hash = hashlib.sha256(VALID_PDF_BYTES).hexdigest().lower()
    assert created_ver.sha256_hash == expected_hash
    assert created_ver.sha256_hash != fake_hash


def test_secretsec_18_environment_config_does_not_expose_secrets_in_root():
    """SECRETSEC-18: Root and health endpoints only expose safe product metadata."""
    with TestClient(app) as test_client:
        root_resp = test_client.get("/")
        health_resp = test_client.get("/health")

    root_data = root_resp.json()
    health_data = health_resp.json()

    # Verify expected public fields
    assert "product" in root_data
    assert "tagline" in root_data
    assert "status" in root_data

    assert health_data["status"] == "ok"
    assert "service" in health_data

    # Verify no sensitive settings leaked
    for data in (root_data, health_data):
        assert "jwt_secret_key" not in data
        assert "database_url" not in data
        assert "storage_dir" not in data


def test_secretsec_19_gitignore_protects_local_artifacts():
    """SECRETSEC-19: .gitignore contains critical patterns for sensitive and ephemeral artifacts."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    gitignore_file = repo_root / ".gitignore"
    assert gitignore_file.is_file()

    content = gitignore_file.read_text(encoding="utf-8")
    required_patterns = [
        ".env",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "storage/",
        "__pycache__/",
        ".pytest_cache/",
        ".venv/",
        "node_modules/",
        "dist/",
    ]
    for pat in required_patterns:
        assert pat in content, f"Missing pattern '{pat}' in .gitignore"


def test_secretsec_20_dependency_and_lockfile_consistency():
    """SECRETSEC-20: Backend requirements and frontend package-lock are present and valid."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    req_file = repo_root / "backend" / "requirements.txt"
    lock_file = repo_root / "frontend" / "package-lock.json"

    assert req_file.is_file()
    assert lock_file.is_file()

    req_text = req_file.read_text(encoding="utf-8")
    assert "fastapi" in req_text
    assert "PyJWT" in req_text
    assert "SQLAlchemy" in req_text


# ===========================================================================
# DEMO MODE SECURITY TESTS (SECRETSEC-DEMO-01 to SECRETSEC-DEMO-06)
# ===========================================================================

def test_secretsec_demo_01_demo_mode_false_blocks_tampering(secretsec_fixture):
    """SECRETSEC-DEMO-01: When DEMO_MODE=false, tampering endpoint returns 403 DEMO_MODE_REQUIRED."""
    client = secretsec_fixture["client"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]
    so_token = secretsec_fixture["so_token"]

    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "DEMO_MODE_REQUIRED"


def test_secretsec_demo_02_demo_mode_true_requires_authentication(secretsec_fixture, monkeypatch):
    """SECRETSEC-DEMO-02: Even with DEMO_MODE=true, unauthenticated requests return 401."""
    client = secretsec_fixture["client"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]

    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper")
    assert resp.status_code == 401


def test_secretsec_demo_03_demo_mode_true_requires_correct_role(secretsec_fixture, monkeypatch):
    """SECRETSEC-DEMO-03: With DEMO_MODE=true, Legal Reviewer or Auditor roles receive 403 Forbidden."""
    client = secretsec_fixture["client"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]
    auditor_token = secretsec_fixture["auditor_token"]

    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp.status_code == 403


def test_secretsec_demo_04_demo_mode_true_requires_case_assignment(secretsec_fixture, monkeypatch):
    """SECRETSEC-DEMO-04: With DEMO_MODE=true, an officer not assigned to the case returns 404."""
    client = secretsec_fixture["client"]
    db = secretsec_fixture["db"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]

    unassigned_io = User(
        username="unassigned_io_demo",
        display_name="Unassigned IO",
        role="IO",
        is_active=True,
    )
    db.add(unassigned_io)
    db.commit()

    token = create_access_token(unassigned_io)
    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_secretsec_demo_05_tamper_endpoint_cannot_accept_arbitrary_storage_path(secretsec_fixture, monkeypatch):
    """SECRETSEC-DEMO-05: Client cannot pass custom storage paths to tamper arbitrary filesystem files."""
    client = secretsec_fixture["client"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]
    so_token = secretsec_fixture["so_token"]

    monkeypatch.setattr(settings, "demo_mode", True)

    # Attempt to inject custom storage path in form/json body
    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        json={"storage_path": "../../secret.txt"},
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert resp.status_code == 200
    # The tamper service only operates on version.storage_key within settings.storage_dir
    data = resp.json()
    assert data["simulation_type"] == "SYNTHETIC_STORAGE_BYTE_CORRUPTION"
    assert data["demo_mode"] is True


def test_secretsec_demo_06_tamper_endpoint_cannot_modify_another_cases_document(secretsec_fixture, monkeypatch):
    """SECRETSEC-DEMO-06: Tamper endpoint enforces IDOR protection across cases."""
    client = secretsec_fixture["client"]
    db = secretsec_fixture["db"]
    doc = secretsec_fixture["doc"]
    version = secretsec_fixture["version"]

    # Create Case 2 with officer assigned ONLY to Case 2
    case_2_officer = User(
        username="case2_only_officer",
        display_name="Case 2 Officer",
        role="IO",
        is_active=True,
    )
    case_2 = Case(case_number="HYD-DEMO-2026-9999", title="Case 2", status="OPEN")
    db.add_all([case_2_officer, case_2])
    db.flush()
    db.add(CaseAssignment(case_id=case_2.id, user_id=case_2_officer.id, is_active=True))
    db.commit()

    token_case_2 = create_access_token(case_2_officer)
    monkeypatch.setattr(settings, "demo_mode", True)

    # Attempt to tamper Case 1 document using Case 2 officer token -> 404
    resp = client.post(
        f"/api/v1/demo/documents/{doc.id}/versions/{version.id}/tamper",
        headers={"Authorization": f"Bearer {token_case_2}"},
    )
    assert resp.status_code == 404
