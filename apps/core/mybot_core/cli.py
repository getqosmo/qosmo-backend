"""MyBot Core CLI.

The local agent runtime. In the shipped product this is the process running on
the MyBot Core in the user's home; in development it is the same code on a
laptop.

Commands::

    mybot init          create the database schema
    mybot demo          reset and seed a full demo owner
    mybot serve         run the API
    mybot scan          run one proactive pass for every owner
    mybot brief         print today's brief
    mybot verify-audit  check every owner's audit chain
    mybot worry         print "what do I need to worry about?"
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys

import sqlalchemy as sa
from mybot_schemas.config import get_settings
from mybot_schemas.db.scope import session_owner_scope, session_system_scope
from mybot_schemas.db.session import create_all, get_engine, session_scope
from mybot_schemas.models import User
from mybot_security.logging import configure_logging, get_logger

log = get_logger(__name__)

BANNER = """
  MyBot  ·  your life, running itself
  local-first personal operating system — v0.1.0
"""


def _registry():
    from mybot_integrations.registry import build_default_registry

    return build_default_registry(get_settings().integrations_mode)


def _vault(session):
    from mybot_security.hardware.keystore import build_keystore
    from mybot_security.vault import Vault

    settings = get_settings()
    return Vault(
        keystore=build_keystore(
            settings.vault_keystore, data_dir=settings.data_dir, env_key=settings.vault_master_key
        ),
        data_dir=settings.data_dir,
    )


def cmd_init(_args) -> int:
    create_all()
    print(f"Schema created at {get_settings().database_url}")
    return 0


def cmd_demo(args) -> int:
    """Reset local state and seed the demo owner."""
    from mybot_core.seed import DEMO_EMAIL, DEMO_PASSWORD, seed_demo

    settings = get_settings()
    if args.reset:
        _reset_database()

    create_all()
    registry = _registry()

    with session_scope() as session:
        with session_system_scope(session, "demo seeding creates a brand new owner"):
            existing = session.execute(
                sa.select(User).where(User.email == DEMO_EMAIL)
            ).scalar_one_or_none()
        if existing is not None and not args.reset:
            print(f"Demo owner {DEMO_EMAIL} already exists. Use --reset to recreate.")
            owner_id = existing.id
        else:
            vault = _vault(session)
            with session_system_scope(session, "demo seeding runs before an owner exists"):
                user = seed_demo(session, registry, vault)
                owner_id = user.id

    # The seeded connectors are in-process, so the sync and scan must run
    # against the same registry instance.
    with session_scope() as session:
        from mybot_services.brief.service import BriefService
        from mybot_services.proactive.engine import ProactiveEngine
        from mybot_services.proactive.sync import ConnectorSync

        with session_owner_scope(session, owner_id):
            sync = ConnectorSync(session, registry).sync_all(owner_id)
            scan = ProactiveEngine(session).scan(owner_id)
            coverage = {
                "calendar": {"ok": "calendar" not in sync.unavailable},
                "email": {"ok": "email" not in sync.unavailable},
            }
            brief = BriefService(session).generate(owner_id, coverage=coverage)

    print(BANNER)
    print(f"  Demo owner : {DEMO_EMAIL}")
    print(f"  Password   : {DEMO_PASSWORD}")
    print(f"  Database   : {settings.database_url}")
    print(f"  Connectors : {settings.integrations_mode} (simulated — no real accounts involved)")
    print(f"  Synced     : {sync.calendar_events} events, {sync.emails} messages")
    print(f"  Inbox      : {scan.cards_created} cards created, {scan.cards_updated} updated")
    print()
    _print_brief(brief)
    print("\n  Next:  mybot serve      (API on http://localhost:8000)")
    print("         cd apps/web && npm install && npm run dev\n")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    settings = get_settings()
    create_all()
    print(BANNER)
    print(f"  API      : http://{args.host}:{args.port}")
    print(f"  Docs     : http://{args.host}:{args.port}/docs")
    print(f"  Env      : {settings.env}\n")
    uvicorn.run(
        "mybot_api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_config=None,
    )
    return 0


def cmd_scan(_args) -> int:
    """Run one proactive pass for every owner."""
    from mybot_services.proactive.engine import ProactiveEngine
    from mybot_services.proactive.sync import ConnectorSync

    registry = _registry()
    total = 0
    with session_scope() as session:
        for owner_id in _all_owner_ids(session):
            with session_owner_scope(session, owner_id):
                sync = ConnectorSync(session, registry).sync_all(owner_id)
                report = ProactiveEngine(session).scan(owner_id)
                total += report.cards_created
                print(
                    f"  {owner_id[:8]}  synced {sync.calendar_events} events / {sync.emails} emails"
                    f"  ·  {report.cards_created} new cards, {report.cards_updated} updated"
                    + (f"  ·  unavailable: {', '.join(sync.unavailable)}" if sync.unavailable else "")
                )
    print(f"\n{total} new inbox cards.")
    return 0


def cmd_brief(_args) -> int:
    from mybot_services.brief.service import BriefService

    with session_scope() as session:
        for owner_id in _all_owner_ids(session):
            with session_owner_scope(session, owner_id):
                brief = BriefService(session).generate(owner_id, persist=False)
                _print_brief(brief)
    return 0


def cmd_worry(_args) -> int:
    from mybot_services.brief.service import BriefService

    with session_scope() as session:
        for owner_id in _all_owner_ids(session):
            with session_owner_scope(session, owner_id):
                report = BriefService(session).worry_report(owner_id)
                print("\nWhat needs you:\n")
                for group, items in report["groups"].items():
                    print(f"  {group}")
                    for item in items:
                        print(f"    • {item['explanation']}")
                    print()
                print(f"  {report['closing']}\n")
    return 0


def cmd_verify_audit(_args) -> int:
    from mybot_services.audit.service import AuditService

    ok = True
    with session_scope() as session:
        for owner_id in _all_owner_ids(session):
            with session_owner_scope(session, owner_id):
                result = AuditService(session).verify_chain(owner_id)
                status = "OK" if result.ok else "TAMPERED"
                print(f"  {owner_id[:8]}  {status}  ({result.checked} events)")
                if not result.ok:
                    ok = False
                    print(f"      problem at sequence {result.first_bad_sequence}: {result.problem}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------


def _all_owner_ids(session) -> list[str]:
    with session_system_scope(session, "CLI iterates every owner on this Core"):
        return [row[0] for row in session.execute(sa.select(User.id)).all()]


def _print_brief(brief) -> None:
    print(f"  {brief.greeting}")
    print(f"  {dt.datetime.now().strftime('%A, %B %-d')}")
    print(f"  {brief.summary}\n")
    for index, line in enumerate(brief.needs_you, start=1):
        print(f"    {index}. {line.text}")
    if brief.handled:
        print("\n  MyBot handled:")
        for line in brief.handled:
            print(f"    ✓ {line.text}")
    if brief.schedule:
        print("\n  Today:")
        for line in brief.schedule:
            print(f"    {line.text}")
    print(f"\n  {brief.closing}")


def _reset_database() -> None:
    """Drop local state. Only ever used by `mybot demo --reset`."""
    settings = get_settings()
    url = settings.database_url
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        if path and path != ":memory:":
            from pathlib import Path

            for suffix in ("", "-wal", "-shm", "-journal"):
                candidate = Path(path + suffix)
                if candidate.exists():
                    candidate.unlink()
        return

    from mybot_schemas.db.base import Base

    engine = get_engine()
    Base.metadata.drop_all(engine)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybot", description="MyBot Core")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database schema").set_defaults(func=cmd_init)

    demo = sub.add_parser("demo", help="seed a full demo owner")
    demo.add_argument("--reset", action="store_true", help="wipe local state first")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="run the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    sub.add_parser("scan", help="run one proactive pass").set_defaults(func=cmd_scan)
    sub.add_parser("brief", help="print today's brief").set_defaults(func=cmd_brief)
    sub.add_parser("worry", help="print what needs attention").set_defaults(func=cmd_worry)
    sub.add_parser("verify-audit", help="verify audit chain integrity").set_defaults(
        func=cmd_verify_audit
    )

    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level, json_output=False)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
