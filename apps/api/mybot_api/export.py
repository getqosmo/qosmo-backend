"""The canonical "everything MyBot holds about you" payload.

Extracted from the export endpoint so that the API route and ``mybot backup``
produce *the same bytes*. A backup that quietly omits a table the export
includes is the kind of thing nobody discovers until they need the backup, and
by then the data is gone.

It lives beside the serialisers rather than in ``mybot_services`` because it is
built entirely from them, and they are the allowlist that keeps
``password_hash`` and ``ciphertext`` out of responses. Duplicating that
allowlist one layer down would mean maintaining two of them, and the second one
would drift.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.models import (
    ActionProposal,
    CalendarEvent,
    Document,
    EmailMessage,
    Entity,
    Fact,
    InboxItem,
    Memory,
    Obligation,
    Relationship,
    User,
)

from .serializers import (
    action_out,
    audit_out,
    document_out,
    entity_out,
    fact_out,
    inbox_item_out,
    memory_out,
    obligation_out,
)

EXPORT_FORMAT = "mybot-export-v1"

#: What the export refuses to include, stated in the payload itself so a person
#: reading a five-year-old file knows what is *not* there.
SECRETS_NOTE = (
    "Vault secrets are not included. They are encrypted with a key held by your "
    "keystore and are not exportable through the API."
)


def build_export_payload(*, db, audit, owner_id: str, user: User) -> dict:
    """Walk every domain model this owner has and serialise it.

    Secrets are excluded by construction: this walks the domain models, not
    ``vault_secrets``, and every field that appears went through a named
    serialiser.
    """

    def _all(model):
        return list(db.execute(sa.select(model).where(model.owner_id == owner_id)).scalars())

    return {
        "format": EXPORT_FORMAT,
        "exported_at": dt.datetime.now(dt.UTC).isoformat(),
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "timezone": user.timezone,
        },
        "entities": [entity_out(e) for e in _all(Entity)],
        "facts": [fact_out(f) for f in _all(Fact)],
        "relationships": [
            {
                "id": r.id,
                "from_id": r.from_id,
                "to_id": r.to_id,
                "type": r.relation_type,
                "attributes": r.attributes,
                "confidence": r.confidence,
            }
            for r in _all(Relationship)
        ],
        "memories": [memory_out(m) for m in _all(Memory)],
        "obligations": [obligation_out(o) for o in _all(Obligation)],
        "inbox_items": [inbox_item_out(i) for i in _all(InboxItem)],
        "documents": [document_out(d) for d in _all(Document)],
        "calendar_events": [
            {
                "id": e.id,
                "title": e.title,
                "start": e.start_at.isoformat(),
                "end": e.end_at.isoformat(),
                "location": e.location,
            }
            for e in _all(CalendarEvent)
        ],
        "emails": [
            {
                "id": e.id,
                "from": e.from_address,
                "subject": e.subject,
                "received_at": e.received_at.isoformat(),
                "classification": e.classification_label,
            }
            for e in _all(EmailMessage)
        ],
        "actions": [action_out(a) for a in _all(ActionProposal)],
        "audit": [audit_out(e) for e in audit.list_events(owner_id, limit=500)],
        "audit_verification": audit.verify_chain(owner_id).as_dict(),
        "note": SECRETS_NOTE,
    }


__all__ = ["EXPORT_FORMAT", "SECRETS_NOTE", "build_export_payload"]
