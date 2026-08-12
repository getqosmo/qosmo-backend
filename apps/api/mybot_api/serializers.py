"""Explicit serialisers.

Every API response is built by a named function here rather than by dumping an
ORM object. That is deliberate: automatic serialisation is how ``password_hash``,
``token_hash``, ``nonce`` and ``ciphertext`` end up in a JSON payload the day
someone adds a column. An allowlist per resource means a new sensitive field is
invisible to the API until somebody consciously exposes it.
"""

from __future__ import annotations

import datetime as dt

from mybot_schemas.actions import ACTION_REGISTRY
from mybot_schemas.models import (
    ActionProposal,
    AuditEvent,
    Document,
    Entity,
    Fact,
    InboxItem,
    Memory,
    Obligation,
)


def _iso(value):
    return value.isoformat() if value is not None else None


def entity_out(entity: Entity, *, facts: list[Fact] | None = None) -> dict:
    payload = {
        "id": entity.id,
        "type": entity.entity_type,
        "name": entity.name,
        "summary": entity.summary,
        "attributes": entity.attributes or {},
        "aliases": entity.aliases or [],
        "classification": entity.classification,
        "confidence": entity.confidence,
        "source": {
            "kind": entity.source_kind,
            "id": entity.source_id,
            "detail": entity.source_detail,
            "inferred": entity.inferred,
        },
        "archived": entity.archived,
        "created_at": _iso(entity.created_at),
        "updated_at": _iso(entity.updated_at),
    }
    if facts is not None:
        payload["facts"] = [fact_out(f) for f in facts]
    return payload


def fact_out(fact: Fact) -> dict:
    return {
        "id": fact.id,
        "key": fact.key,
        "value": (fact.value or {}).get("value"),
        "confidence": fact.confidence,
        "evidence": fact.evidence,
        "classification": fact.classification,
        "source": {"kind": fact.source_kind, "id": fact.source_id, "inferred": fact.inferred},
        "observed_at": _iso(fact.observed_at),
        "superseded": fact.superseded_by_id is not None,
        "superseded_at": _iso(fact.superseded_at),
    }


def memory_out(memory: Memory) -> dict:
    return {
        "id": memory.id,
        "kind": memory.kind,
        "subject": memory.subject,
        "content": memory.content,
        "structured": memory.structured or {},
        "tags": memory.tags or [],
        "classification": memory.classification,
        "confidence": memory.confidence,
        "source": {"kind": memory.source_kind, "id": memory.source_id, "inferred": memory.inferred},
        "entity_id": memory.entity_id,
        "archived": memory.archived,
        "superseded_by_id": memory.superseded_by_id,
        "created_at": _iso(memory.created_at),
        "updated_at": _iso(memory.updated_at),
    }


def obligation_out(obligation: Obligation) -> dict:
    return {
        "id": obligation.id,
        "title": obligation.title,
        "description": obligation.description,
        "kind": obligation.kind,
        "status": obligation.status,
        "due_at": _iso(obligation.due_at),
        "recurrence": obligation.recurrence,
        "amount": obligation.amount,
        "currency": obligation.currency,
        "consequence": obligation.consequence,
        "confidence": obligation.confidence,
        "source": {
            "kind": obligation.source_kind,
            "detail": obligation.source_detail,
            "ids": obligation.source_ids or [],
            "inferred": obligation.inferred,
        },
        "entity_id": obligation.entity_id,
        "recommended_action_type": obligation.recommended_action_type,
        "depends_on_ids": obligation.depends_on_ids or [],
        "completed_at": _iso(obligation.completed_at),
        "created_at": _iso(obligation.created_at),
    }


def inbox_item_out(item: InboxItem) -> dict:
    return {
        "id": item.id,
        "category": item.category,
        "urgency": item.urgency,
        "priority_score": item.priority_score,
        "state": item.state,
        "title": item.title,
        "explanation": item.explanation,
        "reason": item.reason,
        "confidence": item.confidence,
        "rule_id": item.rule_id,
        "source_ids": item.source_ids or [],
        "evidence": item.evidence or [],
        "obligation_id": item.obligation_id,
        "entity_id": item.entity_id,
        "action_proposal_id": item.action_proposal_id,
        "possible_actions": item.possible_actions or [],
        "recommended_action": item.recommended_action,
        "due_at": _iso(item.due_at),
        "snoozed_until": _iso(item.snoozed_until),
        "created_at": _iso(item.created_at),
    }


def action_out(proposal: ActionProposal) -> dict:
    spec = ACTION_REGISTRY.get(proposal.action_type)
    return {
        "id": proposal.id,
        "action_type": proposal.action_type,
        "display": spec.display if spec else proposal.action_type,
        "reversible": spec.reversible if spec else False,
        "external": spec.external_mutation if spec else False,
        "integration": spec.integration if spec else None,
        "params": proposal.params or {},
        "status": proposal.status,
        "risk": proposal.risk,
        "base_risk": proposal.base_risk,
        "requested_by": {
            "type": proposal.requested_by_type,
            "id": proposal.requested_by_id,
            "label": proposal.requested_by_label,
        },
        "reason": proposal.reason,
        "source_ids": proposal.source_ids or [],
        "evidence": proposal.evidence or [],
        "assumptions": proposal.assumptions or [],
        "confidence": proposal.confidence,
        "derived_from_untrusted": proposal.derived_from_untrusted,
        "untrusted_source_ids": proposal.untrusted_source_ids or [],
        "requires_approval": proposal.requires_approval,
        "required_auth_level": proposal.required_auth_level,
        "policy": {
            "outcome": proposal.policy_outcome,
            "rule_id": proposal.policy_rule_id,
            "reasons": proposal.policy_reasons or [],
        },
        "expires_at": _iso(proposal.expires_at),
        "execution": {
            "outcome": proposal.execution_outcome,
            "result": proposal.execution_result,
            "error": proposal.execution_error,
            "executed_at": _iso(proposal.executed_at),
        },
        "created_at": _iso(proposal.created_at),
    }


def action_summary(session, owner_id: str, proposal: ActionProposal) -> dict | None:
    """A human-readable before/after for the approval sheet.

    Derived here from the proposal's parameters and the records they reference
    -- never supplied by the client. The approval is bound to a hash of the
    parameters, so if the *displayed* summary could be set independently, a
    caller could show one thing and have another happen. Computing it from the
    same source removes that gap.

    Returns ``None`` when there is nothing meaningful to render, and the UI
    falls back to the parameter list.
    """
    import sqlalchemy as sa
    from mybot_schemas.models import CalendarEvent

    params = proposal.params or {}

    if proposal.action_type in ("calendar.reschedule", "calendar.cancel"):
        event = session.execute(
            sa.select(CalendarEvent).where(
                CalendarEvent.owner_id == owner_id,
                CalendarEvent.external_id == params.get("event_id", ""),
            )
        ).scalar_one_or_none()
        if event is None:
            return None
        summary = {
            "kind": "calendar",
            "subject": event.title,
            "from_label": "Currently",
            "from_value": event.start_at.strftime("%A %-d %B, %-I:%M %p"),
            "location": event.location,
        }
        if proposal.action_type == "calendar.reschedule" and params.get("new_start"):
            moved = dt.datetime.fromisoformat(params["new_start"])
            summary["to_label"] = "Move to"
            summary["to_value"] = moved.strftime("%A %-d %B, %-I:%M %p")
            summary["shift_days"] = abs((moved - event.start_at).days)
        else:
            summary["to_label"] = "Change"
            summary["to_value"] = "Cancelled"
        return summary

    if proposal.action_type in ("email.draft", "email.send"):
        return {
            "kind": "email",
            "subject": params.get("subject", ""),
            "to": params.get("to", []),
            "body": params.get("body", ""),
        }

    if "amount" in params:
        return {
            "kind": "payment",
            "amount": params.get("amount"),
            "currency": params.get("currency", "USD"),
            "payee": params.get("payee") or params.get("destination_ref"),
            "account_ref": params.get("account_ref"),
            "memo": params.get("memo") or params.get("invoice_id"),
        }

    if proposal.action_type == "obligation.create":
        return {
            "kind": "obligation",
            "subject": params.get("title", ""),
            "from_label": "Due",
            "from_value": params.get("due_date", ""),
            "to_label": "Tracked as",
            "to_value": params.get("kind", "generic"),
        }

    return None


def audit_out(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "sequence": event.sequence,
        "timestamp": _iso(event.timestamp),
        "actor": {"type": event.actor_type, "id": event.actor_id},
        "event_type": event.event_type,
        "resource": {"type": event.resource_type, "id": event.resource_id},
        "request_id": event.request_id,
        "reason": event.reason,
        "model_used": event.model_used,
        "policy_rule": event.policy_rule,
        "approval": {
            "method": event.approval_method,
            "auth_level": event.approval_auth_level,
        },
        "integration": event.integration,
        "result": event.result,
        "details": event.details or {},
        "previous_event_hash": event.previous_event_hash,
        "event_hash": event.event_hash,
    }


def document_out(document: Document) -> dict:
    return {
        "id": document.id,
        "filename": document.filename,
        "mime_type": document.mime_type,
        "byte_size": document.byte_size,
        "sha256": document.sha256,
        "document_type": document.document_type,
        "issuer": document.issuer,
        "folder": document.folder,
        "classification": document.classification,
        "extraction_status": document.extraction_status,
        "extraction_error": document.extraction_error,
        "fields": document.extracted_fields or [],
        "entity_id": document.entity_id,
        "created_at": _iso(document.created_at),
        # Note: `extracted_text` and `storage_path` are intentionally absent.
        # The text is untrusted content and the path is an implementation
        # detail; neither belongs in a list response.
    }


__all__ = [
    "action_out",
    "action_summary",
    "audit_out",
    "document_out",
    "entity_out",
    "fact_out",
    "inbox_item_out",
    "memory_out",
    "obligation_out",
]
