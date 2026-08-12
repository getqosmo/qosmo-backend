"""Shared test fixtures.

Every test runs against a fresh in-memory SQLite database with the real
schema, the real audit triggers and the real owner guard installed. Nothing is
stubbed out that carries a security property -- if a test passes here, the
mechanism it exercises is the one that runs in production.

Two owners (``alice`` and ``bob``) exist in most fixtures so cross-owner
isolation can be asserted rather than assumed.
"""

from __future__ import annotations

import datetime as dt
import os
import tempfile
from pathlib import Path

import pytest

# Configure before anything imports settings.
_TMP = tempfile.mkdtemp(prefix="mybot-test-")
os.environ["MYBOT_DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["MYBOT_DATA_DIR"] = _TMP
os.environ["MYBOT_ENV"] = "test"
os.environ["MYBOT_LLM_DEFAULT_PROVIDER"] = "mock"
os.environ["MYBOT_INTEGRATIONS_MODE"] = "mock"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

from mybot_integrations.registry import build_default_registry  # noqa: E402
from mybot_schemas.config import get_settings, reset_settings_cache  # noqa: E402
from mybot_schemas.db.scope import session_owner_scope, session_system_scope  # noqa: E402
from mybot_schemas.db.session import (  # noqa: E402
    configure_engine,
    create_all,
    create_engine_from_settings,
    get_session_factory,
)
from mybot_schemas.enums import ActorType, AuthLevel  # noqa: E402
from mybot_schemas.models import User  # noqa: E402
from mybot_security.auth import hash_password  # noqa: E402
from mybot_security.hardware.keystore import build_keystore  # noqa: E402
from mybot_security.vault import Vault  # noqa: E402
from mybot_services.action_firewall.service import ActionFirewall  # noqa: E402
from mybot_services.audit.service import AuditService  # noqa: E402
from mybot_services.brief.service import BriefService  # noqa: E402
from mybot_services.inbox.service import InboxService  # noqa: E402
from mybot_services.life_graph.service import LifeGraphService  # noqa: E402
from mybot_services.memory.service import MemoryService  # noqa: E402
from mybot_services.obligations.service import ObligationService  # noqa: E402
from mybot_services.policy.service import PolicyService  # noqa: E402
from mybot_services.proactive.engine import ProactiveEngine  # noqa: E402
from mybot_services.proactive.sync import ConnectorSync  # noqa: E402
from mybot_services.security_center.service import SecurityCenterService  # noqa: E402

TEST_PASSWORD = "test-password-12345"


@pytest.fixture(scope="function")
def engine():
    reset_settings_cache()
    eng = create_engine_from_settings("sqlite+pysqlite:///:memory:")
    configure_engine(eng)
    create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def registry():
    return build_default_registry("mock")


@pytest.fixture
def vault():
    settings = get_settings()
    return Vault(
        keystore=build_keystore("software", data_dir=Path(_TMP)),
        data_dir=settings.data_dir,
    )


def _make_user(db, email: str, name: str) -> User:
    with session_system_scope(db, "test fixture creates an owner"):
        user = User(
            email=email,
            display_name=name,
            password_hash=hash_password(TEST_PASSWORD),
        )
        db.add(user)
        db.flush()
    return user


@pytest.fixture
def alice(db):
    return _make_user(db, "alice@example.com", "Alice Example")


@pytest.fixture
def bob(db):
    return _make_user(db, "bob@example.com", "Bob Example")


@pytest.fixture
def as_alice(db, alice):
    """Bind the session to Alice for the duration of a test."""
    with session_owner_scope(db, alice.id) as owner_id:
        yield owner_id


@pytest.fixture
def as_bob(db, bob):
    with session_owner_scope(db, bob.id) as owner_id:
        yield owner_id


class Services:
    """Convenience bundle mirroring the API's ServiceBundle."""

    def __init__(self, db, registry, vault):
        self.db = db
        self.registry = registry
        self.vault = vault
        self.audit = AuditService(db)
        self.policy = PolicyService(db, self.audit)
        self.firewall = ActionFirewall(db, registry, policy=self.policy, audit=self.audit)
        self.graph = LifeGraphService(db, self.audit)
        self.memory = MemoryService(db, self.audit)
        self.obligations = ObligationService(db, self.audit)
        self.inbox = InboxService(db, self.audit)
        self.brief = BriefService(db, audit=self.audit)
        self.proactive = ProactiveEngine(db)
        self.sync = ConnectorSync(db, registry, self.audit)
        self.security = SecurityCenterService(
            db, policy=self.policy, firewall=self.firewall, audit=self.audit
        )


@pytest.fixture
def services(db, registry, vault):
    return Services(db, registry, vault)


@pytest.fixture
def grant(services):
    """Helper that creates a permission rule the way a human would."""

    def _grant(owner_id: str, action_type: str, **kwargs):
        return services.policy.create_rule(
            owner_id,
            action_type=action_type,
            actor_type=ActorType.USER,
            auth_level=AuthLevel.STRONG,
            created_by="test-user",
            **kwargs,
        )

    return _grant


@pytest.fixture
def now():
    return dt.datetime.now(dt.UTC)


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------


@pytest.fixture
def api(engine):
    """A TestClient wired to the test database.

    The dependency override replaces only the session factory; authentication,
    owner binding, policy and audit all run for real.
    """
    from fastapi.testclient import TestClient
    from mybot_api.deps import get_db
    from mybot_api.main import app

    def _get_db():
        session = get_session_factory()()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def registered(api):
    """Register an owner through the real API and return their credentials."""

    def _register(email: str = "owner@example.com", name: str = "Test Owner"):
        response = api.post(
            "/api/v1/auth/register",
            json={"email": email, "display_name": name, "password": TEST_PASSWORD},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        return {
            "token": body["access_token"],
            "user_id": body["user"]["id"],
            "totp_secret": body["development_totp_secret"],
            "headers": {"Authorization": f"Bearer {body['access_token']}"},
        }

    return _register


@pytest.fixture
def elevate(api):
    """Elevate a session to STRONG using its development TOTP secret."""

    def _elevate(account: dict):
        from mybot_security.auth import totp_code

        response = api.post(
            "/api/v1/auth/elevate",
            json={"code": totp_code(account["totp_secret"])},
            headers=account["headers"],
        )
        assert response.status_code == 200, response.text
        return response.json()

    return _elevate
