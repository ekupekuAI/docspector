"""Tests for Docspector Case Listing and Case Access APIs.

Milestone 7: Protected GET /api/v1/cases and GET /api/v1/cases/{case_id}
enforcing server-side authorization and IDOR protection.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, User
from app.db.session import get_db
from app.main import app
from scripts.seed_demo import seed_demo_data


@pytest.fixture
def cases_client():
    """Create an isolated test client with seeded database and multi-case fixture."""
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

    # Seed baseline demo data (Case 1: HYD-CYB-2026-0147 assigned to all 4 demo users)
    session = TestingSessionLocal()
    seed_demo_data(session)

    io_user = session.query(User).filter(User.username == "docspector.io").first()
    so_user = session.query(User).filter(User.username == "docspector.so").first()

    # 1. Inactive user for testing access denial
    inactive_user = User(
        username="docspector.inactive",
        display_name="Inactive Officer",
        role="IO",
        is_active=False,
    )
    # 2. Active user with no case assignments
    unassigned_user = User(
        username="docspector.unassigned",
        display_name="Unassigned Officer",
        role="IO",
        is_active=True,
    )

    # 3. Case 2: assigned ONLY to SO
    case_2 = Case(
        case_number="HYD-FIN-2026-0888",
        title="Synthetic Financial Audit Review",
        description="Confidential case assigned exclusively to supervising officer.",
        status="OPEN",
    )

    # 4. Case 3: assigned to IO, but assignment is INACTIVE (is_active=False)
    case_3 = Case(
        case_number="HYD-MED-2026-0001",
        title="Synthetic Inactive Assignment Case",
        description="Case where assignment was deactivated.",
        status="OPEN",
    )

    # 5. Case 4: unassigned to anyone
    case_4 = Case(
        case_number="HYD-UNASSIGNED-9999",
        title="Synthetic Fully Unassigned Case",
        description="Case with zero active assignments.",
        status="OPEN",
    )

    session.add_all([inactive_user, unassigned_user, case_2, case_3, case_4])
    session.flush()

    # Assignment for Case 2 -> SO only
    assignment_case_2 = CaseAssignment(
        case_id=case_2.id,
        user_id=so_user.id,
        is_active=True,
    )
    # Inactive assignment for Case 3 -> IO
    assignment_case_3 = CaseAssignment(
        case_id=case_3.id,
        user_id=io_user.id,
        is_active=False,
    )
    session.add_all([assignment_case_2, assignment_case_3])
    session.commit()

    case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()
    case_1_id = case_1.id
    case_2_id = case_2.id
    case_3_id = case_3.id
    case_4_id = case_4.id

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield {
            "client": client,
            "session": session,
            "case_1_id": case_1_id,
            "case_2_id": case_2_id,
            "case_3_id": case_3_id,
            "case_4_id": case_4_id,
            "inactive_user": inactive_user,
        }

    app.dependency_overrides.clear()
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def get_auth_token(client: TestClient, username: str) -> str:
    """Helper to login synthetic user and return access token."""
    resp = client.post("/api/v1/auth/login", json={"username": username})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.json()}"
    return resp.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    """Helper to return Bearer authorization header."""
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# CASE-01: Authenticated assigned user can list their assigned case
# ==============================================================================
def test_case_01_authenticated_assigned_user_can_list_cases(cases_client):
    """CASE-01: Authenticated assigned user can list their assigned case."""
    client = cases_client["client"]
    token = get_auth_token(client, "docspector.io")

    response = client.get("/api/v1/cases", headers=auth_headers(token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["case_number"] == "HYD-CYB-2026-0147"
    assert data[0]["title"] == "Synthetic Cyber Evidence Review"
    assert data[0]["status"] == "OPEN"


# ==============================================================================
# CASE-02: Unauthenticated user cannot list cases
# ==============================================================================
def test_case_02_unauthenticated_user_cannot_list_cases(cases_client):
    """CASE-02: Unauthenticated user cannot list cases (HTTP 401)."""
    client = cases_client["client"]

    response = client.get("/api/v1/cases")
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


# ==============================================================================
# CASE-03: Inactive authenticated user cannot access cases
# ==============================================================================
def test_case_03_inactive_authenticated_user_cannot_access_cases(cases_client):
    """CASE-03: Inactive authenticated user cannot access cases (HTTP 401)."""
    client = cases_client["client"]
    inactive_user = cases_client["inactive_user"]
    token = create_access_token(inactive_user)

    # Listing cases with inactive user token
    list_resp = client.get("/api/v1/cases", headers=auth_headers(token))
    assert list_resp.status_code == 401

    # Case detail with inactive user token
    detail_resp = client.get(
        f"/api/v1/cases/{cases_client['case_1_id']}", headers=auth_headers(token)
    )
    assert detail_resp.status_code == 401


# ==============================================================================
# CASE-04: Case listing returns only cases assigned to the authenticated user
# ==============================================================================
def test_case_04_listing_returns_only_assigned_cases(cases_client):
    """CASE-04: Case listing returns only cases assigned to the authenticated user."""
    client = cases_client["client"]
    so_token = get_auth_token(client, "docspector.so")

    response = client.get("/api/v1/cases", headers=auth_headers(so_token))
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    case_numbers = {c["case_number"] for c in data}
    assert case_numbers == {"HYD-CYB-2026-0147", "HYD-FIN-2026-0888"}


# ==============================================================================
# CASE-05: User assigned to Case A does not receive Case B in the case list
# ==============================================================================
def test_case_05_user_assigned_to_case_a_does_not_receive_case_b(cases_client):
    """CASE-05: User assigned to Case A does not receive Case B in the case list."""
    client = cases_client["client"]
    io_token = get_auth_token(client, "docspector.io")

    response = client.get("/api/v1/cases", headers=auth_headers(io_token))
    assert response.status_code == 200
    data = response.json()
    case_numbers = [c["case_number"] for c in data]
    assert "HYD-CYB-2026-0147" in case_numbers
    assert "HYD-FIN-2026-0888" not in case_numbers


# ==============================================================================
# CASE-06: Assigned user can retrieve their assigned case by case_id
# ==============================================================================
def test_case_06_assigned_user_can_retrieve_case_by_id(cases_client):
    """CASE-06: Assigned user can retrieve their assigned case by case_id."""
    client = cases_client["client"]
    case_1_id = cases_client["case_1_id"]
    io_token = get_auth_token(client, "docspector.io")

    response = client.get(f"/api/v1/cases/{case_1_id}", headers=auth_headers(io_token))
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == case_1_id
    assert data["case_number"] == "HYD-CYB-2026-0147"
    assert data["title"] == "Synthetic Cyber Evidence Review"
    assert data["status"] == "OPEN"
    assert "created_at" in data


# ==============================================================================
# CASE-07: User assigned to Case A cannot retrieve Case B (IDOR protection)
# ==============================================================================
def test_case_07_user_assigned_to_case_a_cannot_retrieve_case_b(cases_client):
    """CASE-07: User assigned to Case A cannot retrieve Case B (returns 404)."""
    client = cases_client["client"]
    case_2_id = cases_client["case_2_id"]  # Assigned exclusively to SO
    io_token = get_auth_token(client, "docspector.io")

    response = client.get(f"/api/v1/cases/{case_2_id}", headers=auth_headers(io_token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"


# ==============================================================================
# CASE-08: Nonexistent case returns 404
# ==============================================================================
def test_case_08_nonexistent_case_returns_404(cases_client):
    """CASE-08: Nonexistent case returns 404."""
    client = cases_client["client"]
    token = get_auth_token(client, "docspector.io")

    response = client.get("/api/v1/cases/99999", headers=auth_headers(token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"


# ==============================================================================
# CASE-09: Unassigned existing case returns the same 404 as nonexistent case
# ==============================================================================
def test_case_09_unassigned_case_matches_nonexistent_case_response(cases_client):
    """CASE-09: Unassigned existing case returns same externally visible 404 behavior as nonexistent case."""
    client = cases_client["client"]
    case_2_id = cases_client["case_2_id"]
    io_token = get_auth_token(client, "docspector.io")

    # Access unassigned existing case
    unassigned_resp = client.get(
        f"/api/v1/cases/{case_2_id}",
        headers={**auth_headers(io_token), "X-Request-ID": "case-enum-probe"},
    )
    # Access nonexistent case
    nonexistent_resp = client.get(
        "/api/v1/cases/99999",
        headers={**auth_headers(io_token), "X-Request-ID": "case-enum-probe"},
    )

    assert unassigned_resp.status_code == 404
    assert nonexistent_resp.status_code == 404
    # Must be byte-for-byte identical to prevent case enumeration
    assert unassigned_resp.json() == nonexistent_resp.json()
    assert unassigned_resp.json()["error"]["code"] == "CASE_ACCESS_DENIED"
    assert unassigned_resp.json()["error"]["message"] == "Case not found"


# ==============================================================================
# CASE-10: Changing case_id in URL cannot bypass authorization
# ==============================================================================
def test_case_10_changing_case_id_cannot_bypass_authorization(cases_client):
    """CASE-10: Changing the case_id in the URL cannot bypass authorization."""
    client = cases_client["client"]
    case_1_id = cases_client["case_1_id"]
    case_2_id = cases_client["case_2_id"]
    case_4_id = cases_client["case_4_id"]
    io_token = get_auth_token(client, "docspector.io")

    # Authorized on Case 1
    resp_valid = client.get(f"/api/v1/cases/{case_1_id}", headers=auth_headers(io_token))
    assert resp_valid.status_code == 200

    # Tampering case_id to unassigned case or nonexistent case
    for tampered_id in [case_2_id, case_4_id, 88888, 12345]:
        resp_tampered = client.get(
            f"/api/v1/cases/{tampered_id}", headers=auth_headers(io_token)
        )
        assert resp_tampered.status_code == 404
        assert resp_tampered.json()["detail"] == "Case not found"


# ==============================================================================
# CASE-11: Role alone does not grant case access
# ==============================================================================
def test_case_11_role_alone_does_not_grant_case_access(cases_client):
    """CASE-11: Role alone does not grant case access to unassigned cases."""
    client = cases_client["client"]
    case_4_id = cases_client["case_4_id"]  # Zero assignments

    # Test all 4 seeded roles: none can access Case 4 without an active assignment
    all_users = ["docspector.io", "docspector.so", "docspector.legal", "docspector.auditor"]
    for username in all_users:
        token = get_auth_token(client, username)

        # GET detail returns 404
        detail_resp = client.get(f"/api/v1/cases/{case_4_id}", headers=auth_headers(token))
        assert detail_resp.status_code == 404, f"Role alone granted detail access to {username}"

        # Case 4 must not appear in case listing
        list_resp = client.get("/api/v1/cases", headers=auth_headers(token))
        assert list_resp.status_code == 200
        case_ids_in_list = [c["id"] for c in list_resp.json()]
        assert case_4_id not in case_ids_in_list, f"Role alone listed unassigned case for {username}"


# ==============================================================================
# CASE-12: Inactive case assignment does not grant access
# ==============================================================================
def test_case_12_inactive_case_assignment_does_not_grant_access(cases_client):
    """CASE-12: Inactive case assignment does not grant access."""
    client = cases_client["client"]
    case_3_id = cases_client["case_3_id"]  # Assigned to IO, but is_active=False
    io_token = get_auth_token(client, "docspector.io")

    # Detail request returns 404
    detail_resp = client.get(f"/api/v1/cases/{case_3_id}", headers=auth_headers(io_token))
    assert detail_resp.status_code == 404
    assert detail_resp.json()["detail"] == "Case not found"

    # Listing does not include Case 3
    list_resp = client.get("/api/v1/cases", headers=auth_headers(io_token))
    assert list_resp.status_code == 200
    case_ids = [c["id"] for c in list_resp.json()]
    assert case_3_id not in case_ids


# ==============================================================================
# CASE-13: All four seeded roles can access a case when actively assigned
# ==============================================================================
def test_case_13_all_four_roles_can_access_when_assigned(cases_client):
    """CASE-13: All four seeded roles can access Case 1 where they all have active assignments."""
    client = cases_client["client"]
    case_1_id = cases_client["case_1_id"]

    roles = ["docspector.io", "docspector.so", "docspector.legal", "docspector.auditor"]
    for username in roles:
        token = get_auth_token(client, username)

        # Each user can retrieve detail
        detail_resp = client.get(f"/api/v1/cases/{case_1_id}", headers=auth_headers(token))
        assert detail_resp.status_code == 200, f"Detail failed for {username}"
        assert detail_resp.json()["id"] == case_1_id

        # Case 1 is in each user's list
        list_resp = client.get("/api/v1/cases", headers=auth_headers(token))
        assert list_resp.status_code == 200, f"List failed for {username}"
        case_ids = [c["id"] for c in list_resp.json()]
        assert case_1_id in case_ids, f"Case 1 missing in list for {username}"


# ==============================================================================
# CASE-14: Response does not expose internal/security-sensitive fields
# ==============================================================================
def test_case_14_response_does_not_expose_internal_fields(cases_client):
    """CASE-14: Response schema does not expose internal SQLAlchemy state or sensitive fields."""
    client = cases_client["client"]
    case_1_id = cases_client["case_1_id"]
    token = get_auth_token(client, "docspector.io")

    response = client.get(f"/api/v1/cases/{case_1_id}", headers=auth_headers(token))
    assert response.status_code == 200
    data = response.json()

    # Allowed public fields
    expected_fields = {"id", "case_number", "title", "description", "status", "created_at"}
    assert set(data.keys()) == expected_fields

    # Forbidden internal/sensitive fields
    forbidden_substrings = [
        "password",
        "secret",
        "token",
        "hash",
        "file_path",
        "storage",
        "instance_state",
        "_sa",
    ]
    for key in data.keys():
        for forbidden in forbidden_substrings:
            assert forbidden not in key.lower(), f"Sensitive key exposed: {key}"


# ==============================================================================
# CASE-15: Server-side authorization ignores client-supplied user identity
# ==============================================================================
def test_case_15_server_side_authorization_ignores_client_supplied_identity(cases_client):
    """CASE-15: Server-side database authorization derives identity strictly from JWT, not client parameters."""
    client = cases_client["client"]
    case_2_id = cases_client["case_2_id"]  # Assigned to SO (user_id=2)
    io_token = get_auth_token(client, "docspector.io")  # IO (user_id=1)

    # IO attempts to spoof user_id or role in headers and query params
    spoofed_headers = {
        "Authorization": f"Bearer {io_token}",
        "X-User-Id": "2",
        "X-Role": "SO",
        "user_id": "2",
    }
    # Spoofed attempt to list cases
    list_resp = client.get("/api/v1/cases?user_id=2&role=SO", headers=spoofed_headers)
    assert list_resp.status_code == 200
    case_ids = [c["id"] for c in list_resp.json()]
    assert case_2_id not in case_ids  # Case 2 remains hidden

    # Spoofed attempt to access Case 2
    detail_resp = client.get(
        f"/api/v1/cases/{case_2_id}?user_id=2&role=SO", headers=spoofed_headers
    )
    assert detail_resp.status_code == 404
    assert detail_resp.json()["detail"] == "Case not found"


# ==============================================================================
# CASE-16: Active unassigned user gets empty list
# ==============================================================================
def test_case_16_active_unassigned_user_gets_empty_list(cases_client):
    """CASE-16: Active user with zero assignments receives an empty list."""
    client = cases_client["client"]
    token = get_auth_token(client, "docspector.unassigned")

    response = client.get("/api/v1/cases", headers=auth_headers(token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0
