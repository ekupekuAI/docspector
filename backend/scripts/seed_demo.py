import os
import sys
from typing import Any

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from sqlalchemy.orm import Session

from app.db.models import Case, CaseAssignment, User
from app.db.session import SessionLocal

SEED_USERS = [
    {
        "username": "docspector.io",
        "display_name": "Investigation Officer",
        "role": "IO",
        "is_active": True,
    },
    {
        "username": "docspector.so",
        "display_name": "Supervising Officer",
        "role": "SO",
        "is_active": True,
    },
    {
        "username": "docspector.legal",
        "display_name": "Legal Reviewer",
        "role": "Legal Reviewer",
        "is_active": True,
    },
    {
        "username": "docspector.auditor",
        "display_name": "Audit Officer",
        "role": "Auditor",
        "is_active": True,
    },
]

SEED_CASE = {
    "case_number": "HYD-CYB-2026-0147",
    "title": "Synthetic Cyber Evidence Review",
    "description": (
        "Synthetic demonstration case for Docspector custody, integrity, "
        "and authorization workflows. Contains no real investigative, "
        "police, victim, or court data."
    ),
    "status": "OPEN",
}


def seed_demo_data(db: Session) -> dict[str, Any]:
    """Seed synthetic demo users, case, and assignments idempotently."""
    results: dict[str, Any] = {
        "users": {},
        "case": {},
        "assignments": {},
    }

    # 1. Seed Users
    seeded_users: dict[str, User] = {}
    for user_data in SEED_USERS:
        existing_user = db.query(User).filter(User.username == user_data["username"]).first()
        if existing_user:
            seeded_users[user_data["role"]] = existing_user
            results["users"][user_data["username"]] = "already exists (reused)"
        else:
            new_user = User(**user_data)
            db.add(new_user)
            db.flush()
            seeded_users[user_data["role"]] = new_user
            results["users"][user_data["username"]] = "created"

    # 2. Seed Fictional Case
    existing_case = db.query(Case).filter(Case.case_number == SEED_CASE["case_number"]).first()
    if existing_case:
        seeded_case = existing_case
        results["case"][SEED_CASE["case_number"]] = "already exists (reused)"
    else:
        new_case = Case(**SEED_CASE)
        db.add(new_case)
        db.flush()
        seeded_case = new_case
        results["case"][SEED_CASE["case_number"]] = "created"

    # 3. Seed Case Assignments
    for role, user in seeded_users.items():
        existing_assignment = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == seeded_case.id,
                CaseAssignment.user_id == user.id,
            )
            .first()
        )
        if existing_assignment:
            results["assignments"][role] = "already exists (reused)"
        else:
            assignment = CaseAssignment(
                case_id=seeded_case.id,
                user_id=user.id,
                is_active=True,
            )
            db.add(assignment)
            results["assignments"][role] = "created"

    return results


def main() -> None:
    db: Session = SessionLocal()
    try:
        results = seed_demo_data(db)
        db.commit()

        print("\nDocspector demo seed")
        print("--------------------")
        print("Users:")
        for username, status in results["users"].items():
            print(f"  {username:<20} -> {status}")

        print("\nCase:")
        for case_number, status in results["case"].items():
            print(f"  {case_number:<20} -> {status}")

        print("\nAssignments:")
        for role, status in results["assignments"].items():
            print(f"  {role:<20} -> {status}")

        print("\nSeed completed successfully.\n")
    except Exception as e:
        db.rollback()
        print(f"\nError running seed: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
