from collections.abc import Callable, Iterable
from enum import StrEnum

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.case_assignment import CaseAssignment
from app.db.models.user import User
from app.db.session import get_db


class Role(StrEnum):
    """Synthetic application roles for Docspector.

    Docspector enforces strict server-side role-based access control.
    These roles correspond exactly to the defined synthetic demo roles.
    """

    IO = "IO"
    SO = "SO"
    LEGAL_REVIEWER = "Legal Reviewer"
    AUDITOR = "Auditor"


ROLE_IO = Role.IO.value
ROLE_SO = Role.SO.value
ROLE_LEGAL_REVIEWER = Role.LEGAL_REVIEWER.value
ROLE_AUDITOR = Role.AUDITOR.value

ALL_ROLES: frozenset[str] = frozenset({role.value for role in Role})


def check_user_role(user: User, allowed_roles: Iterable[str]) -> None:
    """Validate that an authenticated user is active and has an allowed role.

    Deny-by-default security policy:
    - Authorization is strictly enforced on the server-side.
    - Inactive users are rejected with HTTP 403 Forbidden.
    - Unsupported or unknown roles are rejected with HTTP 403 Forbidden.
    - Roles not present in allowed_roles are rejected with HTTP 403 Forbidden.

    403 vs 404 policy:
    An authenticated user attempting a known operation without the required role receives
    HTTP 403 Forbidden because the operation is known and the caller lacks privilege.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    if user.role not in ALL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unsupported user role",
        )

    if user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: insufficient role permissions",
        )


def verify_case_assignment(db: Session, user: User, case_id: int) -> Case:
    """Verify that a case exists and the user has an active assignment to it.

    Server-side authorization and object-level isolation (preventing IDOR):
    - Role checks alone are NOT sufficient for accessing case-scoped resources.
    - An assignment must exist in the database and be marked active.
    - Authorization fails closed: if the case does not exist OR the user is not actively
      assigned to it, HTTP 404 Not Found is returned.

    403 vs 404 policy:
    To prevent unauthorized users from enumerating case existence, requests for cases
    that either do not exist or are not assigned to the user return identical 404 responses.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    if user.role not in ALL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unsupported user role",
        )

    if case_id <= 0 or case_id > 2147483647:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if assignment is None:
        # Non-disclosure: Return 404 to avoid revealing case existence to unassigned users
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    return case


def require_role(*allowed_roles: str) -> Callable[[User], User]:
    """FastAPI dependency factory enforcing role authorization.

    Requires an authenticated active user whose role is in allowed_roles.
    Fails closed with HTTP 403 Forbidden on role mismatch.
    """
    if not allowed_roles:
        raise ValueError("require_role requires at least one allowed role")

    for role in allowed_roles:
        if role not in ALL_ROLES:
            raise ValueError(f"Unknown role specified in authorization rule: {role}")

    def role_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        check_user_role(current_user, allowed_roles)
        return current_user

    return role_dependency


def require_case_assignment(
    case_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    """FastAPI dependency enforcing case assignment authorization.

    Verifies that the authenticated user has an active server-side assignment
    to the requested case_id. Fails closed with HTTP 404 Not Found if unassigned
    or nonexistent.
    """
    return verify_case_assignment(db, current_user, case_id)


def require_case_access(*allowed_roles: str) -> Callable[..., Case]:
    """FastAPI dependency factory combining role validation and case assignment.

    Enforces that:
    1. The authenticated user is active and holds one of allowed_roles (403 on mismatch).
    2. The authenticated user is actively assigned to case_id in the database (404 on mismatch/not found).

    Returns the validated Case model instance.
    """
    if not allowed_roles:
        raise ValueError("require_case_access requires at least one allowed role")

    for role in allowed_roles:
        if role not in ALL_ROLES:
            raise ValueError(f"Unknown role specified in authorization rule: {role}")

    def case_access_dependency(
        case_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> Case:
        check_user_role(current_user, allowed_roles)
        return verify_case_assignment(db, current_user, case_id)

    return case_access_dependency
