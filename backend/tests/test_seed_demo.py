import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import (
    Case,
    CaseAssignment,
    CustodyEvent,
    Document,
    DocumentVersion,
    IntegrityAlert,
    Transfer,
    User,
)
from scripts.seed_demo import SEED_CASE, SEED_USERS, seed_demo_data


@pytest.fixture
def test_db_session():
    """Create an isolated in-memory SQLite database and session for seed testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.rollback()
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_seed_creates_expected_users(test_db_session):
    """TEST 1 — Seed creates exactly four active users with expected roles and usernames."""
    seed_demo_data(test_db_session)
    test_db_session.commit()

    users = test_db_session.query(User).all()
    assert len(users) == 4

    user_map = {u.username: u for u in users}
    expected_roles = {
        "docspector.io": "IO",
        "docspector.so": "SO",
        "docspector.legal": "Legal Reviewer",
        "docspector.auditor": "Auditor",
    }

    for username, role in expected_roles.items():
        assert username in user_map
        assert user_map[username].role == role
        assert user_map[username].is_active is True


def test_seed_creates_expected_case(test_db_session):
    """TEST 2 — Seed creates exactly one fictional case HYD-CYB-2026-0147."""
    seed_demo_data(test_db_session)
    test_db_session.commit()

    cases = test_db_session.query(Case).all()
    assert len(cases) == 1
    case = cases[0]
    assert case.case_number == "HYD-CYB-2026-0147"
    assert case.title == "Synthetic Cyber Evidence Review"
    assert case.status == "OPEN"


def test_seed_creates_four_case_assignments(test_db_session):
    """TEST 3 — Seed creates four case assignments connecting all seeded users to the case."""
    seed_demo_data(test_db_session)
    test_db_session.commit()

    case = test_db_session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()
    assert case is not None

    assignments = test_db_session.query(CaseAssignment).filter(CaseAssignment.case_id == case.id).all()
    assert len(assignments) == 4

    assigned_user_ids = {a.user_id for a in assignments}
    all_user_ids = {u.id for u in test_db_session.query(User).all()}
    assert assigned_user_ids == all_user_ids

    for a in assignments:
        assert a.is_active is True


def test_seed_is_idempotent(test_db_session):
    """TEST 4 — Seed is idempotent when executed multiple times on the same database."""
    # First execution
    res1 = seed_demo_data(test_db_session)
    test_db_session.commit()

    assert all(status == "created" for status in res1["users"].values())
    assert res1["case"][SEED_CASE["case_number"]] == "created"
    assert all(status == "created" for status in res1["assignments"].values())

    # Second execution
    res2 = seed_demo_data(test_db_session)
    test_db_session.commit()

    assert all("already exists" in status for status in res2["users"].values())
    assert "already exists" in res2["case"][SEED_CASE["case_number"]]
    assert all("already exists" in status for status in res2["assignments"].values())

    # Verify counts in database remain identical
    assert test_db_session.query(User).count() == 4
    assert test_db_session.query(Case).count() == 1
    assert test_db_session.query(CaseAssignment).count() == 4


def test_seed_does_not_create_future_workflow_data(test_db_session):
    """TEST 5 — Seed does not create future workflow entities (documents, transfers, events, alerts)."""
    seed_demo_data(test_db_session)
    test_db_session.commit()

    assert test_db_session.query(Document).count() == 0
    assert test_db_session.query(DocumentVersion).count() == 0
    assert test_db_session.query(Transfer).count() == 0
    assert test_db_session.query(CustodyEvent).count() == 0
    assert test_db_session.query(IntegrityAlert).count() == 0


def test_seed_transaction_rollback_on_failure(test_db_session):
    """TEST 6 — Seed rolls back cleanly and leaves no partial state on transaction failure."""
    try:
        seed_demo_data(test_db_session)
        # Simulate an unhandled exception before commit
        raise RuntimeError("Simulated transaction failure during seeding")
    except RuntimeError:
        test_db_session.rollback()

    assert test_db_session.query(User).count() == 0
    assert test_db_session.query(Case).count() == 0
    assert test_db_session.query(CaseAssignment).count() == 0
