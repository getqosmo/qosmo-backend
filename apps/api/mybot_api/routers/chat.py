"""Ask MyBot, documents, and account data export/deletion."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from mybot_schemas.enums import ActorType, AuditEventType, AuthLevel
from mybot_services.chat.service import ChatService
from mybot_services.chat.tools import TOOL_SPECS
from pydantic import BaseModel, Field

from ..deps import (
    Principal,
    ServiceBundle,
    coverage_from_sync,
    get_principal,
    get_services,
    rate_limited,
)
from ..serializers import document_out

router = APIRouter(prefix="/api/v1", tags=["chat"])

#: Uploads above this are refused outright. A generous personal document is
#: well under 25 MB, and an unbounded upload is a trivial disk-exhaustion path.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = None


@router.post("/chat", dependencies=[Depends(rate_limited("chat"))])
def chat(
    payload: ChatIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Answer a question from stored records.

    The reply carries ``citations`` (the record ids behind it) and
    ``grounded_only`` (whether a model was involved at all), so the UI can be
    honest about where an answer came from.
    """
    sync_result = services.sync.sync_all(principal.owner_id)
    services.proactive.scan(principal.owner_id)
    coverage = coverage_from_sync(sync_result)

    service = ChatService(
        services.db, principal.owner_id, firewall=services.firewall, router=services.router
    )
    answer = service.ask(
        payload.message, conversation_id=payload.conversation_id, coverage=coverage
    )
    return answer.as_dict()


@router.get("/chat/tools")
def chat_tools():
    """The complete tool surface available to the reasoning layer.

    Published so the capability boundary is inspectable rather than a claim in
    a document. Anything not listed here, MyBot's reasoning layer cannot do.
    """
    return {
        "tools": TOOL_SPECS,
        "note": (
            "Mutating tools create proposals that a deterministic policy engine evaluates "
            "and a human approves. No tool executes an external action directly, and no "
            "tool can read credentials or grant permissions."
        ),
    }


@router.get("/chat/{conversation_id}/history")
def chat_history(
    conversation_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    service = ChatService(services.db, principal.owner_id, firewall=services.firewall)
    return {
        "items": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "citations": m.citations,
                "created_at": m.created_at.isoformat(),
            }
            for m in service.history(conversation_id)
        ]
    }


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


@router.get("/documents")
def list_documents(
    document_type: str | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    import sqlalchemy as sa
    from mybot_schemas.models import Document

    stmt = sa.select(Document).where(
        Document.owner_id == principal.owner_id, Document.archived.is_(False)
    )
    if document_type:
        stmt = stmt.where(Document.document_type == document_type)
    rows = list(services.db.execute(stmt.order_by(Document.created_at.desc())).scalars())
    return {"items": [document_out(d) for d in rows]}


@router.post(
    "/documents",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited("documents.upload"))],
)
async def upload_document(
    file: UploadFile = File(...),
    folder: str = Form(default="Inbox"),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Ingest a document.

    Contents are encrypted at rest under a Vault-derived key. Extracted values
    carry a confidence and the literal text they came from; a high-confidence
    expiry date becomes a tracked obligation, but nothing irreversible happens
    from extraction alone.
    """
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Files must be under {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file.")

    result = services.documents.ingest(
        principal.owner_id,
        filename=file.filename or "upload",
        content=content,
        mime_type=file.content_type or "application/octet-stream",
        folder=folder,
    )
    services.proactive.scan(principal.owner_id)

    return {
        "document": document_out(result.document),
        "obligations_created": result.obligations_created,
        "entity_id": result.entity_id,
        "warnings": result.warnings,
        "injection_suspected": result.injection_suspected,
    }


# ---------------------------------------------------------------------------
# Ownership: export and deletion
# ---------------------------------------------------------------------------


@router.get("/account/export")
def export_data(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Export everything MyBot holds, in plain JSON.

    Deliberately complete and deliberately boring: entities, facts,
    relationships, memories, obligations, inbox cards, documents metadata,
    actions and the full audit chain. No proprietary format, no partial
    export -- the user owns this.

    Secrets are excluded by construction: the Vault holds ciphertext and this
    export walks the domain models, not ``vault_secrets``.

    The payload itself is built in ``mybot_api.export`` because ``mybot backup``
    seals exactly the same structure.
    """
    from ..export import build_export_payload

    owner_id = principal.owner_id

    payload = build_export_payload(
        db=services.db,
        audit=services.audit,
        owner_id=owner_id,
        user=principal.user,
    )

    services.audit.record(
        owner_id,
        AuditEventType.DATA_EXPORTED,
        actor_type=ActorType.USER,
        actor_id=owner_id,
        reason="owner exported their data",
        result="exported",
        details={"entities": len(payload["entities"]), "memories": len(payload["memories"])},
    )
    return payload


class DeleteDataIn(BaseModel):
    confirm: str = Field(description="Must be the literal string DELETE MY DATA")


@router.post("/account/data/delete")
def delete_personal_data(
    payload: DeleteDataIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Delete personal content.

    Personal content is genuinely removed -- entities, facts, memories,
    obligations, inbox cards, documents (including the encrypted files),
    synced calendar and email.

    The **audit chain is retained**. That is a deliberate, documented
    asymmetry: the security record of *what MyBot did* is what makes the
    system accountable, and it contains references and reasons, not the
    personal content itself. See ``docs/DATA_MODEL.md``. Nothing that a user
    would recognise as "my data" survives this call.
    """
    principal.require(AuthLevel.STRONG)
    if payload.confirm != "DELETE MY DATA":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation phrase did not match.",
        )

    import sqlalchemy as sa
    from mybot_schemas.models import (
        CalendarEvent,
        ChatMessage,
        DailyBrief,
        Document,
        EmailMessage,
        Entity,
        Fact,
        InboxItem,
        Memory,
        Obligation,
        Relationship,
    )

    owner_id = principal.owner_id
    db = services.db
    deleted: dict[str, int] = {}

    # Remove encrypted document files from disk, not just their rows.
    documents = list(
        db.execute(sa.select(Document).where(Document.owner_id == owner_id)).scalars()
    )
    files_removed = 0
    for document in documents:
        path = services.documents.settings.data_dir / document.storage_path
        try:
            if path.exists():
                path.unlink()
                files_removed += 1
        except OSError:  # pragma: no cover
            pass

    for model in (
        Fact, Relationship, InboxItem, Obligation, Memory, Document,
        CalendarEvent, EmailMessage, ChatMessage, DailyBrief, Entity,
    ):
        result = db.execute(sa.delete(model).where(model.owner_id == owner_id))
        deleted[model.__tablename__] = result.rowcount or 0
    db.flush()

    services.audit.record(
        owner_id,
        AuditEventType.DATA_DELETED,
        actor_type=ActorType.USER,
        actor_id=owner_id,
        reason="owner deleted their personal data",
        approval_auth_level=principal.auth_level.value,
        result="deleted",
        details={
            "rows_deleted": deleted,
            "document_files_removed": files_removed,
            "retained": "audit chain only (no personal content)",
        },
    )

    return {
        "deleted": deleted,
        "document_files_removed": files_removed,
        "retained": {
            "audit_events": (
                "The audit chain is retained. It records what MyBot did and why, and "
                "contains references and reasons rather than your personal content. "
                "Deleting it would make the security history unverifiable."
            )
        },
    }
