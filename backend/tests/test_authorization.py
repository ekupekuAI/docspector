"""Tests for Docspector server-side authorization policies and RBAC dependencies.

Milestone 6: Server-side deny-by-default role and case assignment authorization.
"""

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.authorization import (
    ALL_ROLES,
    ROLE_AUDITOR,
    ROLE_IO,
    ROLE_LEGAL_REVIEWER,
    ROLE_SO,
    Role,
    check_user_role,
    require_case_access,
    require_case_assignment,
    require_role,
    verify_case_assignment,
)
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, User
from app.db.session import get_db
from app.main import app as main_app
from scripts.seed_demo import seed_demo_data


@pytest.fixture
def authz_fixture():
    """Create an isolated test client with seeded database and authz test routes."""
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

    # Seed baseline demo data
    session = TestingSessionLocal()
    seed_demo_data(session)

    # Create additional fixture entities for authorization testing:
    # 1. Inactive user
    inactive_user = User(
        username="docspector.inactive",
        display_name="Inactive Officer",
        role=ROLE_IO,
        is_active=False,
    )
    # 2. User with unknown/unsupported role
    bad_role_user = User(
        username="docspector.badrole",
        display_name="Bad Role User",
        role="SuperAdmin",  # Unsupported role
        is_active=True,
    )
    # 3. Active user with no case assignments
    unassigned_user = User(
        username="docspector.unassigned",
        display_name="Unassigned Officer",
        role=ROLE_IO,
        is_active=True,
    )
    # 4. Case B: assigned ONLY to SO (docspector.so)
    so_user = session.query(User).filter(User.username == "docspector.so").first()
    case_b = Case(
        case_number="HYD-FIN-2026-0888",
        title="Synthetic Financial Audit Case B",
        description="Restricted case assigned exclusively to supervising officer.",
        status="OPEN",
    )
    session.add_all([inactive_user, bad_role_user, unassigned_user, case_b])
    session.flush()

    case_b_assignment = CaseAssignment(
        case_id=case_b.id,
        user_id=so_user.id,
        is_active=True,
    )
    # 5. Case C: unassigned to anyone
    case_c = Case(
        case_number="HYD-CYB-2026-9999",
        title="Unassigned Case C",
        description="Case with no active assignments.",
        status="OPEN",
    )
    session.add_all([case_b_assignment, case_c])
    session.commit()

    case_a = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()
    case_a_id = case_a.id
    case_b_id = case_b.id
    case_c_id = case_c.id

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Build dedicated test app with auth and authorization test routes
    test_app = FastAPI()
    from app.api.auth import router as auth_router
    test_app.include_router(auth_router)

    test_router = APIRouter(prefix="/test-authz", tags=["test-authz"])

    @test_router.get("/io-only")
    def io_only_route(current_user: User = Depends(require_role(ROLE_IO))):
        return {"message": "ok", "user": current_user.username, "role": current_user.role}

    @test_router.get("/so-and-legal")
    def so_and_legal_route(
        current_user: User = Depends(require_role(ROLE_SO, ROLE_LEGAL_REVIEWER))
    ):
        return {"message": "ok", "user": current_user.username, "role": current_user.role}

    @test_router.get("/cases/{case_id}/assigned")
    def case_assignment_route(case: Case = Depends(require_case_assignment)):
        return {"message": "ok", "case_id": case.id, "case_number": case.case_number}

    @test_router.get("/cases/{case_id}/io-access")
    def case_io_access_route(case: Case = Depends(require_case_access(ROLE_IO))):
        return {"message": "ok", "case_id": case.id, "case_number": case.case_number}

    @test_router.get("/cases/{case_id}/all-roles-access")
    def case_all_roles_access_route(
        case: Case = Depends(
            require_case_access(ROLE_IO, ROLE_SO, ROLE_LEGAL_REVIEWER, ROLE_AUDITOR)
        )
    ):
        return {"message": "ok", "case_id": case.id, "case_number": case.case_number}

    test_app.include_router(test_router)
    test_app.dependency_overrides[get_db] = override_get_db

    with TestClient(test_app) as client:
        yield {
            "client": client,
            "session": session,
            "db_factory": TestingSessionLocal,
            "case_a_id": case_a_id,
            "case_b_id": case_b_id,
            "case_c_id": case_c_id,
        }

    test_app.dependency_overrides.clear()
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def get_token(client: TestClient, username: str) -> str:
    """Helper to login synthetic user and return access token."""
    resp = client.post("/api/v1/auth/login", json={"username": username})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.json()}"
    return resp.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    """Helper to return Bearer authorization header."""
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# AUTHZ-01: Allowed role passes role authorization
# ==============================================================================
def test_authz_01_allowed_role_passes(authz_fixture):
    """AUTHZ-01: Authenticated active user with an allowed role passes role authorization."""
    client = authz_fixture["client"]
    token = get_token(client, "docspector.io")

    response = client.get("/test-authz/io-only", headers=auth_header(token))
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "ok"
    assert data["user"] == "docspector.io"
    assert data["role"] == "IO"


# ==============================================================================
# AUTHZ-02: Disallowed role receives 403
# ==============================================================================
def test_authz_02_disallowed_role_receives_403(authz_fixture):
    """AUTHZ-02: Authenticated active user with a disallowed role receives 403."""
    client = authz_fixture["client"]

    # SO attempting an IO-only endpoint receives 403
    so_token = get_token(client, "docspector.so")
    response = client.get("/test-authz/io-only", headers=auth_header(so_token))
    assert response.status_code == 403
    assert response.json()["detail"] == "Access forbidden: insufficient role permissions"

    # Auditor attempting SO/Legal-only endpoint receives 403
    auditor_token = get_token(client, "docspector.auditor")
    response_auditor = client.get("/test-authz/so-and-legal", headers=auth_header(auditor_token))
    assert response_auditor.status_code == 403
    assert response_auditor.json()["detail"] == "Access forbidden: insufficient role permissions"


# ==============================================================================
# AUTHZ-03: Unknown/unsupported role is denied
# ==============================================================================
def test_authz_03_unknown_role_is_denied(authz_fixture):
    """AUTHZ-03: Unknown/unsupported role is denied."""
    client = authz_fixture["client"]
    session = authz_fixture["session"]

    bad_user = session.query(User).filter(User.username == "docspector.badrole").first()
    token = create_access_token(bad_user)

    # Calling role-protected endpoint with unsupported role
    response = client.get("/test-authz/io-only", headers=auth_header(token))
    assert response.status_code == 403
    assert response.json()["detail"] == "Unsupported user role"

    # Calling check_user_role directly raises 403
    with pytest.raises(Exception) as exc_info:
        check_user_role(bad_user, [ROLE_IO])
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Unsupported user role"


# ==============================================================================
# AUTHZ-04: Inactive user cannot pass authorization
# ==============================================================================
def test_authz_04_inactive_user_cannot_pass_authorization(authz_fixture):
    """AUTHZ-04: Inactive user cannot pass authorization."""
    client = authz_fixture["client"]
    session = authz_fixture["session"]

    inactive_user = session.query(User).filter(User.username == "docspector.inactive").first()
    token = create_access_token(inactive_user)

    # Inactive user token fails at authentication (get_current_user -> 401)
    response = client.get("/test-authz/io-only", headers=auth_header(token))
    assert response.status_code == 401

    # Direct authorization checks explicitly reject inactive users with 403
    with pytest.raises(Exception) as exc_info_role:
        check_user_role(inactive_user, [ROLE_IO])
    assert exc_info_role.value.status_code == 403
    assert exc_info_role.value.detail == "Inactive user account"

    with pytest.raises(Exception) as exc_info_case:
        verify_case_assignment(session, inactive_user, authz_fixture["case_a_id"])
    assert exc_info_case.value.status_code == 403
    assert exc_info_case.value.detail == "Inactive user account"


# ==============================================================================
# AUTHZ-05: User assigned to Case A passes case-assignment authorization
# ==============================================================================
def test_authz_05_user_assigned_to_case_a_passes(authz_fixture):
    """AUTHZ-05: User assigned to Case A passes case-assignment authorization for Case A."""
    client = authz_fixture["client"]
    case_a_id = authz_fixture["case_a_id"]
    token = get_token(client, "docspector.io")

    response = client.get(f"/test-authz/cases/{case_a_id}/assigned", headers=auth_header(token))
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "ok"
    assert data["case_id"] == case_a_id
    assert data["case_number"] == "HYD-CYB-2026-0147"


# ==============================================================================
# AUTHZ-06: User assigned to Case A cannot access Case B (IDOR protection)
# ==============================================================================
def test_authz_06_user_assigned_to_case_a_cannot_access_case_b(authz_fixture):
    """AUTHZ-06: User assigned to Case A cannot access Case B."""
    client = authz_fixture["client"]
    case_b_id = authz_fixture["case_b_id"]  # Assigned exclusively to SO
    io_token = get_token(client, "docspector.io")

    # IO assigned to Case A attempts to access Case B -> 404 (non-disclosure)
    response = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(io_token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"


# ==============================================================================
# AUTHZ-07: User with no assignment cannot access a protected case
# ==============================================================================
def test_authz_07_unassigned_user_cannot_access_case(authz_fixture):
    """AUTHZ-07: User with no assignment cannot access a protected case."""
    client = authz_fixture["client"]
    case_a_id = authz_fixture["case_a_id"]
    unassigned_token = get_token(client, "docspector.unassigned")

    response = client.get(f"/test-authz/cases/{case_a_id}/assigned", headers=auth_header(unassigned_token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"


# ==============================================================================
# AUTHZ-08: Case assignment is checked server-side using the database
# ==============================================================================
def test_authz_08_case_assignment_checked_server_side_via_database(authz_fixture):
    """AUTHZ-08: Case assignment is checked server-side using the database."""
    client = authz_fixture["client"]
    session = authz_fixture["session"]
    case_b_id = authz_fixture["case_b_id"]
    so_user = session.query(User).filter(User.username == "docspector.so").first()
    so_token = get_token(client, "docspector.so")

    # 1. SO initially has active assignment to Case B -> 200
    res1 = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(so_token))
    assert res1.status_code == 200

    # 2. Deactivate assignment in database
    assignment = (
        session.query(CaseAssignment)
        .filter(CaseAssignment.case_id == case_b_id, CaseAssignment.user_id == so_user.id)
        .first()
    )
    assignment.is_active = False
    session.commit()

    # SO immediately loses access via server-side database check -> 404
    res2 = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(so_token))
    assert res2.status_code == 404
    assert res2.json()["detail"] == "Case not found"

    # 3. Reactivate assignment in database -> 200 again
    assignment.is_active = True
    session.commit()
    res3 = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(so_token))
    assert res3.status_code == 200

    # 4. Delete assignment entirely from database -> 404
    session.delete(assignment)
    session.commit()
    res4 = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(so_token))
    assert res4.status_code == 404


# ==============================================================================
# AUTHZ-09: A role alone does not grant case access
# ==============================================================================
def test_authz_09_role_alone_does_not_grant_case_access(authz_fixture):
    """AUTHZ-09: A role alone does not grant case access."""
    client = authz_fixture["client"]
    case_c_id = authz_fixture["case_c_id"]  # Case with no assignments

    # Test that even privileged roles (SO, Auditor, Legal Reviewer) cannot access unassigned case
    for role_user in ["docspector.io", "docspector.so", "docspector.legal", "docspector.auditor"]:
        token = get_token(client, role_user)
        response = client.get(f"/test-authz/cases/{case_c_id}/assigned", headers=auth_header(token))
        assert response.status_code == 404, f"Role alone granted access to {role_user} on unassigned case"
        assert response.json()["detail"] == "Case not found"


# ==============================================================================
# AUTHZ-10: Nonexistent case returns the correct 404 behavior
# ==============================================================================
def test_authz_10_nonexistent_case_returns_404(authz_fixture):
    """AUTHZ-10: Nonexistent case returns the correct 404 behavior."""
    client = authz_fixture["client"]
    token = get_token(client, "docspector.io")

    response = client.get("/test-authz/cases/99999/assigned", headers=auth_header(token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"


# ==============================================================================
# AUTHZ-11: Object existence is not unnecessarily disclosed (404 policy)
# ==============================================================================
def test_authz_11_object_existence_not_disclosed(authz_fixture):
    """AUTHZ-11: Object existence is not unnecessarily disclosed where the selected policy requires 404."""
    client = authz_fixture["client"]
    case_b_id = authz_fixture["case_b_id"]
    io_token = get_token(client, "docspector.io")

    # Request nonexistent case
    nonexistent_resp = client.get("/test-authz/cases/99999/assigned", headers=auth_header(io_token))
    # Request existing case without assignment
    unassigned_resp = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(io_token))

    # Both must return 404 with identical response body to prevent enumeration
    assert nonexistent_resp.status_code == 404
    assert unassigned_resp.status_code == 404
    assert nonexistent_resp.json() == unassigned_resp.json()
    assert nonexistent_resp.json() == {"detail": "Case not found"}


# ==============================================================================
# AUTHZ-12: Cannot bypass authorization by changing case_id parameter
# ==============================================================================
def test_authz_12_cannot_bypass_by_altering_case_id(authz_fixture):
    """AUTHZ-12: A user cannot bypass authorization by changing the case_id supplied to the authorization dependency."""
    client = authz_fixture["client"]
    case_a_id = authz_fixture["case_a_id"]
    case_b_id = authz_fixture["case_b_id"]
    io_token = get_token(client, "docspector.io")

    # Authorized on Case A
    auth_resp = client.get(f"/test-authz/cases/{case_a_id}/assigned", headers=auth_header(io_token))
    assert auth_resp.status_code == 200

    # User manipulates URL to access Case B or nonexistent ID
    tampered_resp_b = client.get(f"/test-authz/cases/{case_b_id}/assigned", headers=auth_header(io_token))
    assert tampered_resp_b.status_code == 404

    tampered_resp_other = client.get("/test-authz/cases/54321/assigned", headers=auth_header(io_token))
    assert tampered_resp_other.status_code == 404


# ==============================================================================
# AUTHZ-13: All four seeded roles assigned to a case pass combined authorization
# ==============================================================================
def test_authz_13_all_four_roles_assigned_pass(authz_fixture):
    """AUTHZ-13: All four seeded roles (IO, SO, Legal Reviewer, Auditor) assigned to Case A pass combined authorization."""
    client = authz_fixture["client"]
    case_a_id = authz_fixture["case_a_id"]

    roles = ["docspector.io", "docspector.so", "docspector.legal", "docspector.auditor"]
    for username in roles:
        token = get_token(client, username)
        response = client.get(
            f"/test-authz/cases/{case_a_id}/all-roles-access", headers=auth_header(token)
        )
        assert response.status_code == 200, f"Failed for {username}: {response.json()}"
        assert response.json()["case_id"] == case_a_id


# ==============================================================================
# AUTHZ-14: Combined authorization enforces both role and assignment
# ==============================================================================
def test_authz_14_combined_role_and_case_assignment(authz_fixture):
    """AUTHZ-14: Combined authorization enforces both role (403) and assignment (404)."""
    client = authz_fixture["client"]
    case_a_id = authz_fixture["case_a_id"]  # All assigned
    case_b_id = authz_fixture["case_b_id"]  # Only SO assigned

    so_token = get_token(client, "docspector.so")
    # SO is assigned to Case A, but the endpoint requires IO role -> 403 Forbidden
    resp_so_case_a = client.get(f"/test-authz/cases/{case_a_id}/io-access", headers=auth_header(so_token))
    assert resp_so_case_a.status_code == 403
    assert resp_so_case_a.json()["detail"] == "Access forbidden: insufficient role permissions"

    io_token = get_token(client, "docspector.io")
    # IO has the required role (IO), but is NOT assigned to Case B -> 404 Not Found
    resp_io_case_b = client.get(f"/test-authz/cases/{case_b_id}/io-access", headers=auth_header(io_token))
    assert resp_io_case_b.status_code == 404
    assert resp_io_case_b.json()["detail"] == "Case not found"


# ==============================================================================
# AUTHZ-15: Invalid policy configuration fails fast
# ==============================================================================
def test_authz_15_invalid_policy_configuration_fails_fast():
    """AUTHZ-15: Attempting to configure dependencies with unknown roles or empty lists fails fast."""
    with pytest.raises(ValueError, match="Unknown role specified"):
        require_role("InvalidRole")

    with pytest.raises(ValueError, match="require_role requires at least one"):
        require_role()

    with pytest.raises(ValueError, match="Unknown role specified"):
        require_case_access("InvalidRole")

    with pytest.raises(ValueError, match="require_case_access requires at least one"):
        require_case_access()


# ==============================================================================
# AUTHZ-16: Role constants match all seeded synthetic roles
# ==============================================================================
def test_authz_16_role_constants():
    """AUTHZ-16: Role enum and constants match exactly the 4 synthetic roles."""
    expected_roles = {"IO", "SO", "Legal Reviewer", "Auditor"}
    assert ALL_ROLES == expected_roles
    assert Role.IO.value == "IO"
    assert Role.SO.value == "SO"
    assert Role.LEGAL_REVIEWER.value == "Legal Reviewer"
    assert Role.AUDITOR.value == "Auditor"
