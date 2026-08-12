"""Today, Inbox and the morning brief.

The endpoints behind the primary product surface. ``/today`` is what the app
opens to; it runs a connector sync, a proactive scan and a brief generation in
one request so the screen is never stale, and it returns the *coverage* map so
the UI can tell the truth about what was and was not checked.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from mybot_schemas.db.types import utcnow
from pydantic import BaseModel

from ..deps import Principal, ServiceBundle, coverage_from_sync, get_principal, get_services
from ..serializers import inbox_item_out

router = APIRouter(prefix="/api/v1", tags=["today"])


class SnoozeIn(BaseModel):
    hours: int = 24


def _refresh(services: ServiceBundle, owner_id: str) -> dict:
    """Sync connectors and re-run the deterministic scan.

    Returns the coverage map. Sync failures are not fatal -- the product still
    works from what is already stored -- but they *are* reported, because the
    difference between "nothing to worry about" and "I couldn't check" is the
    whole point.
    """
    sync_result = services.sync.sync_all(owner_id)
    services.proactive.scan(owner_id)
    services.firewall.expire_stale(owner_id)
    return coverage_from_sync(sync_result)


@router.get("/today")
def today(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    coverage = _refresh(services, principal.owner_id)
    brief = services.brief.generate(principal.owner_id, coverage=coverage)
    items = services.inbox.list_items(principal.owner_id, limit=50)
    needs = services.inbox.needs_attention(principal.owner_id)

    return {
        "brief": brief.as_dict(),
        "needs_attention_count": len(needs),
        "items": [inbox_item_out(i) for i in items],
        "counts": services.inbox.counts_by_category(principal.owner_id),
        "coverage": coverage,
        "generated_at": utcnow().isoformat(),
    }


@router.get("/brief")
def brief(
    date: str | None = Query(default=None, description="YYYY-MM-DD; defaults to today"),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    if date:
        stored = services.brief.get_stored(principal.owner_id, date)
        if stored is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No brief for that date")
        return {
            "brief_date": stored.brief_date,
            "greeting": stored.greeting,
            "needs_you": stored.needs_you,
            "handled": stored.handled,
            "schedule": stored.schedule,
            "coverage": stored.coverage,
            "facts": stored.facts,
        }
    coverage = _refresh(services, principal.owner_id)
    return services.brief.generate(principal.owner_id, coverage=coverage).as_dict()


@router.get("/worry")
def worry(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """"What do I need to worry about?" as a first-class endpoint.

    Fully deterministic. No model is invoked, so this cannot invent a concern
    and cannot reassure the user unless the systems were genuinely checked.
    """
    coverage = _refresh(services, principal.owner_id)
    return services.brief.worry_report(principal.owner_id, coverage=coverage)


@router.get("/inbox")
def inbox(
    state: str = Query(default="open"),
    category: str | None = Query(default=None),
    limit: int = Query(default=100, le=200),
    refresh: bool = Query(default=False),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    coverage = _refresh(services, principal.owner_id) if refresh else {}
    items = services.inbox.list_items(
        principal.owner_id, state=state, category=category, limit=limit
    )
    return {
        "items": [inbox_item_out(i) for i in items],
        "counts": services.inbox.counts_by_category(principal.owner_id),
        "coverage": coverage,
    }


@router.get("/inbox/{item_id}")
def inbox_item(
    item_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    item = services.inbox.get(principal.owner_id, item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return inbox_item_out(item)


@router.post("/inbox/{item_id}/resolve")
def resolve_item(
    item_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        return inbox_item_out(
            services.inbox.resolve(principal.owner_id, item_id, actor_id=principal.owner_id)
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None


@router.post("/inbox/{item_id}/dismiss")
def dismiss_item(
    item_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        return inbox_item_out(
            services.inbox.dismiss(principal.owner_id, item_id, actor_id=principal.owner_id)
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None


@router.post("/inbox/{item_id}/snooze")
def snooze_item(
    item_id: str,
    payload: SnoozeIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    until = utcnow() + dt.timedelta(hours=max(1, min(payload.hours, 24 * 30)))
    try:
        return inbox_item_out(
            services.inbox.snooze(principal.owner_id, item_id, until, actor_id=principal.owner_id)
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
