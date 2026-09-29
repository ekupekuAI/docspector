import os
import tempfile
from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
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


@pytest.fixture
def db_engine():
    """Create an isolated SQLite database engine with foreign key enforcement."""
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
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Provide a transactional session for testing."""
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db_engine,
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_database_connection(db_engine):
    """TEST 1 — Database connection: Prove database connection and query execution."""
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
        assert result == 1


def test_metadata_contains_all_expected_tables():
    """TEST 2 — Metadata contains all expected tables: Verify all 8 core entities exist."""
    expected_tables = {
        "users",
        "cases",
        "case_assignments",
        "documents",
        "document_versions",
        "transfers",
        "custody_events",
        "integrity_alerts",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert actual_tables == expected_tables


def test_foreign_key_enforcement_invalid_user_reference(db_session):
    """TEST 3 — Foreign-key enforcement: Prove invalid FK reference is rejected by SQLite."""
    # Attempt to insert a document with non-existent case_id and created_by_user_id
    invalid_doc = Document(
        case_id=9999,
        document_number="DOC-001",
        title="Test Document",
        created_by_user_id=9999,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(invalid_doc)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_foreign_key_enforcement_valid_reference(db_session):
    """Verify that inserting valid references succeeds."""
    user = User(
        username="officer1",
        display_name="Officer One",
        role="IO",
        is_active=True,
    )
    case = Case(
        case_number="CASE-001",
        title="Sample Case",
        status="OPEN",
    )
    db_session.add_all([user, case])
    db_session.commit()

    doc = Document(
        case_id=case.id,
        document_number="DOC-001",
        title="Valid Document",
        created_by_user_id=user.id,
    )
    db_session.add(doc)
    db_session.commit()
    assert doc.id is not None


def test_unique_constraint_users_username(db_session):
    """TEST 4 — Unique constraint on users.username."""
    u1 = User(
        username="duplicate_user",
        display_name="User One",
        role="IO",
        is_active=True,
    )
    u2 = User(
        username="duplicate_user",
        display_name="User Two",
        role="SO",
        is_active=True,
    )
    db_session.add(u1)
    db_session.commit()

    db_session.add(u2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_constraint_cases_case_number(db_session):
    """TEST 4 — Unique constraint on cases.case_number."""
    c1 = Case(
        case_number="CASE-UNIQUE-001",
        title="Case 1",
        status="OPEN",
    )
    c2 = Case(
        case_number="CASE-UNIQUE-001",
        title="Case 2",
        status="OPEN",
    )
    db_session.add(c1)
    db_session.commit()

    db_session.add(c2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_constraint_document_version(db_session):
    """TEST 4 — Unique constraint on (document_id, version_number)."""
    user = User(username="doc_creator", display_name="Creator", role="IO")
    case = Case(case_number="CASE-DOC-VER", title="Case For Doc Versions")
    db_session.add_all([user, case])
    db_session.commit()

    doc = Document(
        case_id=case.id,
        document_number="DOC-VER-1",
        title="Document 1",
        created_by_user_id=user.id,
    )
    db_session.add(doc)
    db_session.commit()

    v1 = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        state="STORED",
        original_filename="file_v1.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_key="storage/v1/file_v1.pdf",
        created_by_user_id=user.id,
    )
    v2 = DocumentVersion(
        document_id=doc.id,
        version_number=1,  # Duplicate version number
        state="STORED",
        original_filename="file_v1_dup.pdf",
        mime_type="application/pdf",
        size_bytes=2048,
        sha256_hash="f4b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_key="storage/v1/file_v1_dup.pdf",
        created_by_user_id=user.id,
    )
    db_session.add(v1)
    db_session.commit()

    db_session.add(v2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_constraint_custody_event_sequence(db_session):
    """TEST 4 — Unique constraint on (case_id, sequence_number)."""
    user = User(username="custody_officer", display_name="Officer", role="IO")
    case = Case(case_number="CASE-CUSTODY-SEQ", title="Case For Custody")
    db_session.add_all([user, case])
    db_session.commit()

    now = datetime.now(timezone.utc)
    ev1 = CustodyEvent(
        case_id=case.id,
        sequence_number=1,
        event_type="CASE_CREATED",
        actor_user_id=user.id,
        event_time=now,
        event_hash="hash_0001",
    )
    ev2 = CustodyEvent(
        case_id=case.id,
        sequence_number=1,  # Duplicate sequence number for same case
        event_type="DOCUMENT_ATTACHED",
        actor_user_id=user.id,
        event_time=now,
        event_hash="hash_0002",
    )
    db_session.add(ev1)
    db_session.commit()

    db_session.add(ev2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_constraint_custody_event_hash(db_session):
    """TEST 4 — Unique constraint on event_hash."""
    user = User(username="hash_officer", display_name="Officer", role="IO")
    case1 = Case(case_number="CASE-HASH-1", title="Case 1")
    case2 = Case(case_number="CASE-HASH-2", title="Case 2")
    db_session.add_all([user, case1, case2])
    db_session.commit()

    now = datetime.now(timezone.utc)
    ev1 = CustodyEvent(
        case_id=case1.id,
        sequence_number=1,
        event_type="CASE_CREATED",
        actor_user_id=user.id,
        event_time=now,
        event_hash="global_unique_hash",
    )
    ev2 = CustodyEvent(
        case_id=case2.id,
        sequence_number=1,
        event_type="CASE_CREATED",
        actor_user_id=user.id,
        event_time=now,
        event_hash="global_unique_hash",  # Duplicate event_hash
    )
    db_session.add(ev1)
    db_session.commit()

    db_session.add(ev2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_alembic_migration_upgrade_and_downgrade_temp_db():
    """TEST — Verify Alembic migration upgrade and downgrade on temporary SQLite DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        temp_db_path = tmp.name

    try:
        db_url = f"sqlite:///{temp_db_path}"
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        ini_path = os.path.join(repo_root, "alembic.ini")

        alembic_cfg = Config(ini_path)
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)
        alembic_cfg.set_main_option("script_location", os.path.join(repo_root, "backend", "alembic"))

        # Run upgrade head
        command.upgrade(alembic_cfg, "head")

        # Verify tables exist
        temp_engine = create_engine(db_url)
        with temp_engine.connect() as conn:
            tables = [
                row[0]
                for row in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
                ).fetchall()
            ]
            assert "users" in tables
            assert "cases" in tables
            assert "case_assignments" in tables
            assert "documents" in tables
            assert "document_versions" in tables
            assert "transfers" in tables
            assert "custody_events" in tables
            assert "integrity_alerts" in tables
            assert "alembic_version" in tables

        # Run downgrade base
        command.downgrade(alembic_cfg, "base")

        # Verify domain tables are removed
        with temp_engine.connect() as conn:
            remaining_tables = [
                row[0]
                for row in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'alembic_version';")
                ).fetchall()
            ]
            assert len(remaining_tables) == 0

        temp_engine.dispose()
    finally:
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except OSError:
                pass
