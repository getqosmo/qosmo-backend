"""MyBot Core CLI.

The local agent runtime. In the shipped product this is the process running on
the MyBot Core in the user's home; in development it is the same code on a
laptop.

Commands::

    mybot init          create the database schema
    mybot demo          reset and seed a full demo owner
    mybot serve         run the API
    mybot daemon        run the proactive loop continuously
    mybot scan          run one proactive pass for every owner
    mybot brief         print today's brief
    mybot verify-audit  check every owner's audit chain
    mybot worry         print "what do I need to worry about?"
    mybot backup        write an encrypted backup
    mybot restore       open an encrypted backup
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


def cmd_daemon(args) -> int:
    """Run the proactive loop until interrupted.

    This is the process that makes MyBot proactive rather than
    reactive-when-opened. On the Core it runs continuously in the home.
    """
    from mybot_core.daemon import ProactiveDaemon

    create_all()
    daemon = ProactiveDaemon(registry=_registry(), interval_seconds=args.interval)
    print(BANNER)
    print(f"  Proactive loop every {daemon.interval}s. Ctrl-C to stop.\n")
    if args.once:
        result = daemon.tick()
        print(f"  {result.as_dict()}")
        return 0
    daemon.run_forever()
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


def cmd_backup(args) -> int:
    """Write an encrypted backup of one owner's data.

    Deliberately a *local* command rather than an API endpoint. An endpoint
    that emits a sealed archive plus its recovery phrase over HTTP turns a
    stolen session token into a permanent, offline copy of somebody's life --
    the export endpoint at least gives them plaintext they must keep stealing.
    A backup is a physical act: you run it on your Core.
    """
    from pathlib import Path

    from mybot_api.export import build_export_payload
    from mybot_schemas.enums import ActorType, AuditEventType
    from mybot_security.backup import BackupService, phrase_checksum
    from mybot_services.audit.service import AuditService

    destination = Path(args.output)
    if destination.exists() and not args.force:
        print(f"  {destination} already exists. Use --force to overwrite.")
        return 1

    contacts: dict[str, bytes] = {}
    for spec in args.contact or []:
        if ":" not in spec:
            print(f"  --contact expects NAME:FILE, got {spec!r}")
            return 2
        label, path = spec.split(":", 1)
        material = Path(path).read_bytes()
        if len(material) < 16:
            print(f"  recovery material for {label} is too short to be a secret")
            return 2
        contacts[label] = material

    with session_scope() as session:
        owner_id = _resolve_owner(session, args.owner)
        if owner_id is None:
            return 2
        with session_owner_scope(session, owner_id):
            user = session.get(User, owner_id)
            payload = build_export_payload(
                db=session,
                audit=AuditService(session),
                owner_id=owner_id,
                user=user,
            )
            archive, manifest, phrase = BackupService().create(
                payload=payload,
                owner_id=owner_id,
                recovery_phrase=args.phrase,
                contact_secrets=contacts or None,
            )
            # Recorded because a backup leaving the machine is exactly the kind
            # of event an owner should be able to see afterwards. The phrase is
            # not recorded -- writing it to the audit log would defeat it.
            AuditService(session).record(
                owner_id,
                AuditEventType.DATA_EXPORTED,
                actor_type=ActorType.USER,
                actor_id=owner_id,
                reason="owner created an encrypted backup",
                result="backed up",
                details={
                    "recovery_paths": [w["path"] for w in manifest.wraps],
                    "bytes": len(archive),
                },
            )

    destination.write_bytes(archive)
    destination.chmod(0o600)

    print(f"\n  Backup written to {destination} ({len(archive):,} bytes)")
    print(f"  Recovery paths : {', '.join(w['label'] for w in manifest.wraps)}")

    if phrase:
        words = phrase.split()
        print("\n  ── Recovery phrase ──────────────────────────────────────")
        print("  Write these 24 words down. They are shown once and are not")
        print("  stored anywhere. Without them, and without a recovery contact,")
        print("  this backup cannot be opened -- by you or by anyone else.\n")
        for row in range(0, len(words), 4):
            line = "  ".join(f"{row + i + 1:2}. {w:<10}" for i, w in enumerate(words[row : row + 4]))
            print(f"    {line}")
        print(f"\n  Checksum: {phrase_checksum(phrase)}  (to confirm you copied them correctly)")
        print("  ─────────────────────────────────────────────────────────\n")
    return 0


def cmd_restore(args) -> int:
    """Open a backup and print what it contains.

    Stops short of writing the contents back into the database. Restoring into
    a live Core is a merge problem -- which of two versions of a memory wins,
    what happens to audit chains from a different machine -- and getting that
    wrong silently corrupts the record. Recovering the *data* is the promise
    this closes; re-import is a separate, reviewed piece of work.
    """
    import json
    from pathlib import Path

    from mybot_security.backup import BackupService, RecoveryFailed

    service = BackupService()
    archive = Path(args.archive).read_bytes()

    if args.describe:
        print(json.dumps(service.describe(archive), indent=2))
        return 0

    contact = None
    if args.contact:
        if ":" not in args.contact:
            print("  --contact expects NAME:FILE")
            return 2
        label, path = args.contact.split(":", 1)
        contact = (label, Path(path).read_bytes())

    phrase = args.phrase
    if phrase is None and contact is None:
        import getpass

        phrase = getpass.getpass("  Recovery phrase: ")

    try:
        payload = service.restore(archive, recovery_phrase=phrase, contact_secret=contact)
    except RecoveryFailed as exc:
        print(f"\n  Could not open this backup.\n  {exc}\n")
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2))
        Path(args.output).chmod(0o600)
        print(f"\n  Contents written to {args.output} (plaintext -- handle accordingly)\n")
    else:
        print("\n  Backup opened. Contents:\n")
        for key, value in sorted(payload.items()):
            if isinstance(value, list):
                print(f"    {key:20} {len(value)}")
        print("\n  Re-run with --output FILE to write the full JSON.\n")
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


def _resolve_owner(session, requested: str | None) -> str | None:
    """Pick the owner a single-owner command should act on.

    Prints and returns ``None`` rather than guessing when a Core has several
    owners and none was named -- backing up the wrong person's life silently is
    worse than an error message.
    """
    owner_ids = _all_owner_ids(session)
    if requested:
        with session_system_scope(session, "CLI resolves an owner by id or email"):
            match = session.execute(
                sa.select(User.id).where(sa.or_(User.id == requested, User.email == requested))
            ).scalar_one_or_none()
        if match is None:
            print(f"  No owner matching {requested!r} on this Core.")
            return None
        return match
    if not owner_ids:
        print("  No owners on this Core yet. Run `mybot demo` or register through the API.")
        return None
    if len(owner_ids) > 1:
        print(f"  {len(owner_ids)} owners on this Core. Name one with --owner ID|EMAIL.")
        return None
    return owner_ids[0]


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

    daemon = sub.add_parser("daemon", help="run the proactive loop continuously")
    daemon.add_argument("--interval", type=int, default=None, help="seconds between passes")
    daemon.add_argument("--once", action="store_true", help="run a single pass and exit")
    daemon.set_defaults(func=cmd_daemon)

    sub.add_parser("scan", help="run one proactive pass").set_defaults(func=cmd_scan)
    sub.add_parser("brief", help="print today's brief").set_defaults(func=cmd_brief)
    sub.add_parser("worry", help="print what needs attention").set_defaults(func=cmd_worry)
    sub.add_parser("verify-audit", help="verify audit chain integrity").set_defaults(
        func=cmd_verify_audit
    )

    backup = sub.add_parser("backup", help="write an encrypted backup")
    backup.add_argument("output", help="path to write the archive to")
    backup.add_argument("--owner", help="owner id or email (required if this Core has several)")
    backup.add_argument(
        "--phrase",
        help="use this recovery phrase instead of generating one "
        "(a generated 24-word phrase is stronger; use this only to reuse an existing one)",
    )
    backup.add_argument(
        "--contact",
        action="append",
        metavar="NAME:FILE",
        help="add a recovery contact holding the secret in FILE. Repeatable.",
    )
    backup.add_argument("--force", action="store_true", help="overwrite an existing file")
    backup.set_defaults(func=cmd_backup)

    restore = sub.add_parser("restore", help="open an encrypted backup")
    restore.add_argument("archive", help="path to the backup archive")
    restore.add_argument(
        "--describe",
        action="store_true",
        help="show what the archive is and which recovery paths it accepts, without opening it",
    )
    restore.add_argument(
        "--phrase", help="recovery phrase (prompted for interactively if omitted)"
    )
    restore.add_argument("--contact", metavar="NAME:FILE", help="recover using a contact's secret")
    restore.add_argument("--output", help="write the decrypted contents to this file")
    restore.set_defaults(func=cmd_restore)

    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level, json_output=False)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
