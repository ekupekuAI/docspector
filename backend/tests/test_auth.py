from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.db.base import Base
from app.db.models import User
from app.db.session import get_db
from app.main import app
from scripts.seed_demo import seed_demo_data

settings = get_settings()


@pytest.fixture
def auth_client():
    """Create an isolated test client with seeded database for authentication tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Seed demo users and an inactive user for testing
    session = TestingSessionLocal()
    seed_demo_data(session)
    inactive_user = User(
        username="docspector.inactive",
        display_name="Inactive Officer",
        role="IO",
        is_active=False,
    )
    session.add(inactive_user)
    session.commit()
    session.close()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_login_with_seeded_valid_user(auth_client):
    """TEST 1 — Login with seeded valid user returns token and valid claims."""
    response = auth_client.post(
        "/api/v1/auth/login",
        json={"username": "docspector.io"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == settings.jwt_access_token_expire_minutes * 60

    # Decode and verify payload
    payload = jwt.decode(
        data["access_token"],
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )
    assert "sub" in payload
    assert payload["username"] == "docspector.io"
    assert payload["role"] == "IO"
    assert "iat" in payload
    assert "exp" in payload


def test_login_for_each_role(auth_client):
    """TEST 2 — Login for each synthetic role and verify token role claim."""
    roles_map = {
        "docspector.io": "IO",
        "docspector.so": "SO",
        "docspector.legal": "Legal Reviewer",
        "docspector.auditor": "Auditor",
    }

    for username, expected_role in roles_map.items():
        response = auth_client.post(
            "/api/v1/auth/login",
            json={"username": username},
        )
        assert response.status_code == 200
        token = response.json()["access_token"]
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        assert payload["role"] == expected_role
        assert payload["username"] == username


def test_login_unknown_username(auth_client):
    """TEST 3 — Login with unknown username returns HTTP 401."""
    response = auth_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent.user"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
    assert "WWW-Authenticate" in response.headers


def test_login_inactive_user(auth_client):
    """TEST 4 — Login with inactive user returns HTTP 401."""
    response = auth_client.post(
        "/api/v1/auth/login",
        json={"username": "docspector.inactive"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_missing_authorization_header(auth_client):
    """TEST 5 — GET /api/v1/auth/me without Authorization header returns HTTP 401."""
    response = auth_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_valid_bearer_token(auth_client):
    """TEST 6 — Valid Bearer token allows GET /api/v1/auth/me and returns identity."""
    login_resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username": "docspector.io"},
    )
    token = login_resp.json()["access_token"]

    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "docspector.io"
    assert user_data["role"] == "IO"
    assert user_data["display_name"] == "Investigation Officer"
    assert user_data["is_active"] is True


def test_malformed_token(auth_client):
    """TEST 7 — Malformed token returns HTTP 401."""
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-valid-jwt-token"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_invalid_signature(auth_client):
    """TEST 8 — Token signed with different secret returns HTTP 401."""
    now = datetime.now(timezone.utc)
    fake_token = jwt.encode(
        {"sub": "1", "username": "docspector.io", "role": "IO", "iat": now, "exp": now + timedelta(hours=1)},
        "wrong-secret-key-that-is-at-least-32-bytes-long",
        algorithm=settings.jwt_algorithm,
    )
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {fake_token}"},
    )
    assert response.status_code == 401


def test_expired_token(auth_client):
    """TEST 9 — Expired token returns HTTP 401."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(hours=2)
    expired_token = jwt.encode(
        {"sub": "1", "username": "docspector.io", "role": "IO", "iat": past - timedelta(hours=1), "exp": past},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


def test_missing_subject(auth_client):
    """TEST 10 — Token without 'sub' returns HTTP 401."""
    now = datetime.now(timezone.utc)
    token_without_sub = jwt.encode(
        {"username": "docspector.io", "role": "IO", "iat": now, "exp": now + timedelta(hours=1)},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_without_sub}"},
    )
    assert response.status_code == 401


def test_nonexistent_subject(auth_client):
    """TEST 11 — Token with nonexistent user ID returns HTTP 401."""
    now = datetime.now(timezone.utc)
    token_bad_sub = jwt.encode(
        {"sub": "99999", "username": "nonexistent", "role": "IO", "iat": now, "exp": now + timedelta(hours=1)},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_bad_sub}"},
    )
    assert response.status_code == 401


def test_algorithm_enforcement(auth_client):
    """TEST 12 — Token signed with different algorithm is rejected."""
    now = datetime.now(timezone.utc)
    key_for_hs512 = "a-very-long-secret-key-that-is-at-least-64-bytes-long-for-hs512-algorithm"
    token_hs512 = jwt.encode(
        {"sub": "1", "username": "docspector.io", "role": "IO", "iat": now, "exp": now + timedelta(hours=1)},
        key_for_hs512,
        algorithm="HS512",
    )
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_hs512}"},
    )
    assert response.status_code == 401
