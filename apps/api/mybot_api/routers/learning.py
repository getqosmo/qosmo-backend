"""What MyBot has learned about you, and your controls over it.

This router exists because of a rule that is easy to state and easy to skip:
**a system that learns things about you which you cannot see or change is
surveillance, not assistance.** So every learned preference is readable in
plain language, with the evidence that produced it, and every one can be
corrected, muted or deleted.

Note what has no endpoint here. There is no "apply this learning as a
permission", no "let MyBot decide", no autonomy dial. The strongest thing this
surface can do is *offer* a standing rule — `GET /learning/suggestions` — which
the owner then creates through the permissions API like any other rule. That
separation is Rule 2 as a URL layout: learning lives here, authority lives
somewhere else, and no request to this router can create one from the other.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..deps import Principal, ServiceBundle, get_principal, get_services
from ..serializers import learned_preference_out

router = APIRouter(prefix="/api/v1/learning", tags=["learning"])


class CorrectionIn(BaseModel):
    """The owner telling MyBot it had something wrong.

    The highest-value signal the system receives: unambiguous, owner-authored
    and specific. Applied immediately rather than after N repetitions.
    """

    subject: str = Field(min_length=1, max_length=200)
    correction: str = Field(min_length=1, max_length=2000)
    evidence_ref: str | None = None


@router.get("")
def growth(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Everything MyBot has learned, including what it is deliberately ignoring.

    Quarantined rows — learned from content the owner did not write — are
    included and flagged. Hiding them would be worse: the owner is the only
    party who can tell MyBot that something an email implied about them is
    actually true.
    """
    return services.learning.growth_report(principal.owner_id)


@router.get("/preferences")
def list_preferences(
    kind: str | None = Query(default=None),
    applied_only: bool = Query(default=False),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    if applied_only:
        rows = services.learning.applicable(principal.owner_id, kind=kind)
    else:
        import sqlalchemy as sa
        from mybot_schemas.models import LearnedPreference

        query = sa.select(LearnedPreference).where(
            LearnedPreference.owner_id == principal.owner_id
        )
        if kind:
            query = query.where(LearnedPreference.kind == kind)
        rows = list(services.db.execute(query).scalars())

    return {"preferences": [learned_preference_out(p) for p in rows]}


@router.get("/suggestions")
def suggestions(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Standing rules MyBot would like to offer to set up.

    Read the shape carefully: these are *offers*, each carrying its evidence
    and an explicit ``requires_human_confirmation``. Acting on one means the
    owner creating a permission rule through the permissions API. MyBot noticing
    that you approve something ninety percent of the time is an observation;
    deciding to stop asking would be a permission grant, and this endpoint
    cannot make one.
    """
    return {"suggestions": services.learning.suggestions(principal.owner_id)}


@router.post("/corrections", status_code=status.HTTP_201_CREATED)
def add_correction(
    body: CorrectionIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    row = services.learning.record_correction(
        principal.owner_id,
        subject=body.subject,
        correction=body.correction,
        evidence_ref=body.evidence_ref,
    )
    return learned_preference_out(row)


@router.post("/preferences/{preference_id}/confirm")
def confirm(
    preference_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """"Yes, that's right."

    Promotes an inference to a stated fact: full confidence, never decays. For
    a quarantined row this is also the only thing that lifts the quarantine —
    a human looked at it and vouched for it.
    """
    if not services.learning.confirm(principal.owner_id, preference_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such learned preference.")
    return {"confirmed": True}


@router.post("/preferences/{preference_id}/mute")
def mute(
    preference_id: str,
    muted: bool = Query(default=True),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Stop applying this without deleting the observation.

    Kept rather than deleted so the same behaviour does not immediately
    re-learn it. Being overruled is itself worth remembering.
    """
    if not services.learning.mute(principal.owner_id, preference_id, muted=muted):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such learned preference.")
    return {"muted": muted}


@router.delete("/preferences/{preference_id}")
def forget(
    preference_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """"Forget that." A hard delete, because the word means something."""
    if not services.learning.forget(principal.owner_id, preference_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such learned preference.")
    return {"forgotten": True}
