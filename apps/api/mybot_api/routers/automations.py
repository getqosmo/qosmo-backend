"""Notifications and automations.

Two surfaces that share a theme: MyBot reaching out, and MyBot acting on
standing instructions. Both are deliberately conservative.

Note what creating an automation *cannot* do. `trigger_type` is validated
against a fixed list, because a trigger is a query and arbitrary user-supplied
queries are a bad idea. `action_type` is validated against the action registry.
And the automation still runs through the Action Firewall with
`ActorType.AUTOMATION`, so it can never do something the owner has not
permitted — the worst a misconfigured one produces is a queue of proposals they
decline.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from mybot_schemas.actions import ACTION_REGISTRY
from mybot_schemas.models import AutomationRule
from mybot_services.automations.engine import TRIGGER_TYPES
from pydantic import BaseModel, Field

from ..deps import Principal, ServiceBundle, get_principal, get_services

router = APIRouter(prefix="/api/v1", tags=["automations"])


class AutomationIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    trigger_type: str
    trigger_config: dict = Field(default_factory=dict)
    #: Omit for a notify-only automation. That is often the better choice:
    #: "tell me" rather than "act".
    action_type: str | None = None
    action_params: dict = Field(default_factory=dict)
    enabled: bool = True


def _out(rule: AutomationRule) -> dict:
    spec = ACTION_REGISTRY.get(rule.action_type or "")
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "trigger_type": rule.trigger_type,
        "trigger_config": rule.trigger_config or {},
        "action_type": rule.action_type,
        "action_display": spec.display if spec else None,
        "action_risk": spec.risk.value if spec else None,
        "notify_only": rule.action_type is None,
        "enabled": rule.enabled,
        "run_count": rule.run_count,
        "last_run_at": rule.last_run_at.isoformat() if rule.last_run_at else None,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


@router.get("/notifications")
def list_notifications(
    unread_only: bool = Query(default=False),
    limit: int = Query(default=50, le=200),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    rows = services.notifications.list_for(
        principal.owner_id, unread_only=unread_only, limit=limit
    )
    return {
        "items": [
            {
                "id": n.id,
                "title": n.title,
                "body": n.body,
                "urgency": n.urgency,
                "channel": n.channel,
                "inbox_item_id": n.inbox_item_id,
                "action_proposal_id": n.action_proposal_id,
                "read": n.read_at is not None,
                "created_at": n.created_at.isoformat(),
            }
            for n in rows
        ],
        "unread": services.notifications.unread_count(principal.owner_id),
    }


@router.post("/notifications/{notification_id}/read")
def mark_read(
    notification_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        services.notifications.mark_read(principal.owner_id, notification_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
    return {"ok": True}


@router.post("/notifications/read-all")
def mark_all_read(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    return {"marked": services.notifications.mark_all_read(principal.owner_id)}


# ---------------------------------------------------------------------------
# Automations
# ---------------------------------------------------------------------------


@router.get("/automations")
def list_automations(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    import sqlalchemy as sa

    rows = list(
        services.db.execute(
            sa.select(AutomationRule)
            .where(AutomationRule.owner_id == principal.owner_id)
            .order_by(AutomationRule.created_at.desc())
        ).scalars()
    )
    return {
        "items": [_out(rule) for rule in rows],
        "available_triggers": list(TRIGGER_TYPES),
        "note": (
            "Automations run through the same policy engine as everything else. "
            "Anything above low risk still waits for your approval."
        ),
    }


@router.post("/automations", status_code=status.HTTP_201_CREATED)
def create_automation(
    payload: AutomationIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    if payload.trigger_type not in TRIGGER_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown trigger. Available: {', '.join(TRIGGER_TYPES)}",
        )
    if payload.action_type and payload.action_type not in ACTION_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown action type: {payload.action_type}",
        )

    rule = AutomationRule(
        owner_id=principal.owner_id,
        name=payload.name,
        description=payload.description,
        trigger_type=payload.trigger_type,
        trigger_config=payload.trigger_config,
        action_type=payload.action_type,
        action_params=payload.action_params,
        enabled=payload.enabled,
        created_by=f"user:{principal.user.email}",
    )
    services.db.add(rule)
    services.db.flush()
    return _out(rule)


@router.patch("/automations/{automation_id}")
def toggle_automation(
    automation_id: str,
    enabled: bool = Query(),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    import sqlalchemy as sa

    rule = services.db.execute(
        sa.select(AutomationRule).where(
            AutomationRule.owner_id == principal.owner_id,
            AutomationRule.id == automation_id,
        )
    ).scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    rule.enabled = enabled
    services.db.flush()
    return _out(rule)


@router.delete("/automations/{automation_id}")
def delete_automation(
    automation_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    import sqlalchemy as sa

    result = services.db.execute(
        sa.delete(AutomationRule).where(
            AutomationRule.owner_id == principal.owner_id,
            AutomationRule.id == automation_id,
        )
    )
    if not result.rowcount:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return {"deleted": True, "id": automation_id}


@router.post("/automations/run")
def run_automations(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Run every enabled automation now.

    Exists so a person can see what an automation would do without waiting for
    the next scheduled pass. It has no more authority than the scheduled run.
    """
    return services.automations.run(principal.owner_id).as_dict()
