"""The egress ledger: everything that has left this machine.

The one privacy question that actually settles anything — *show me everything
that left, when, where it went and why* — answered completely rather than
reassuringly. See ``mybot_services.egress`` for why a company whose revenue is
the outbound flow could never ship this endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..deps import Principal, ServiceBundle, get_principal, get_services

router = APIRouter(prefix="/api/v1/egress", tags=["egress"])


@router.get("")
def ledger(
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=200, ge=0, le=1000),
    only_external: bool = Query(default=True),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    return services.egress.ledger(
        principal.owner_id, days=days, limit=limit, only_external=only_external
    )


@router.get("/summary")
def summary(
    days: int = Query(default=30, ge=1, le=365),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """One line for the Security Center, plus the worst case.

    The highest classification *ever* sent is reported separately from the
    window, because somebody deciding whether to trust this wants to know the
    most sensitive thing that ever left, not the typical thing.
    """
    out = services.egress.summary(principal.owner_id, days=days)
    out["highest_ever_sent"] = services.egress.highest_classification_ever_sent(
        principal.owner_id
    )
    return out
