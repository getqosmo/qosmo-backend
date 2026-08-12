"""Action proposals: list, inspect, approve, reject.

The approval endpoints are the highest-value target in the whole API, so the
checks are worth being explicit about:

* The proposal id is resolved *within the owner scope*. Substituting another
  user's action id yields 404.
* The presented auth level is taken from the session, recomputed for
  elevation expiry -- never from the request body.
* Physical presence, when required, is obtained from the presence provider and
  bound to the caller's registered device. A client cannot simply claim it.
* Everything past that is the Action Firewall's job: re-evaluating policy,
  checking the approval has not been used, verifying the parameters still
  match what was shown, and executing exactly once.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from mybot_schemas.actions import ACTION_REGISTRY
from mybot_schemas.enums import ActorType, AuthLevel
from mybot_services.action_firewall.service import ActionRejected, ProposalRequest
from pydantic import BaseModel

from ..deps import Principal, ServiceBundle, get_presence_provider, get_principal, get_services
from ..serializers import action_out, action_summary

router = APIRouter(prefix="/api/v1/actions", tags=["actions"])


class ApproveIn(BaseModel):
    note: str | None = None
    #: Request physical presence. Whether it is *granted* is decided by the
    #: presence provider, not by this flag.
    use_physical_presence: bool = False


class RejectIn(BaseModel):
    note: str | None = None


class ProposeIn(BaseModel):
    """A user-initiated action from the UI.

    Note the absence of ``risk``, ``requires_approval`` and
    ``required_auth_level``: a client cannot suggest them, let alone set them.
    """

    action_type: str
    params: dict
    reason: str | None = None
    resource: str = "*"
    inbox_item_id: str | None = None


@router.get("")
def list_actions(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, le=200),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    proposals = services.firewall.list_proposals(
        principal.owner_id, status=status_filter, limit=limit
    )
    return {
        "items": [action_out(p) for p in proposals],
        "pending": len([p for p in proposals if p.status == "pending_approval"]),
    }


@router.get("/registry")
def action_registry():
    """The action catalogue and its fixed risk classifications.

    Exposed read-only so the UI can render risk badges consistently and so the
    user can see exactly what MyBot is capable of asking for. Nothing about
    this is settable through the API.
    """
    return {
        "actions": [
            {
                "action_type": key,
                "display": spec.display,
                "risk": spec.risk.value,
                "external": spec.external_mutation,
                "reversible": spec.reversible,
                "integration": spec.integration,
                "min_auth": spec.min_auth,
                "tags": list(spec.tags),
            }
            for key, spec in sorted(ACTION_REGISTRY.items())
        ]
    }


@router.get("/{action_id}")
def get_action(
    action_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        proposal = services.firewall.get(principal.owner_id, action_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None

    payload = action_out(proposal)
    payload["summary"] = action_summary(services.db, principal.owner_id, proposal)
    payload["audit"] = [
        {
            "sequence": e.sequence,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "result": e.result,
            "reason": e.reason,
            "actor": e.actor_type,
        }
        for e in services.audit.list_events(principal.owner_id, resource_id=action_id, limit=50)
    ]
    return payload


@router.post("", status_code=status.HTTP_201_CREATED)
def propose(
    payload: ProposeIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Create a proposal from a direct user interaction.

    Marked ``ActorType.USER`` because a human clicked it -- which is what
    allows action types outside the agent-proposable set. The policy engine
    still applies in full.
    """
    try:
        proposal = services.firewall.propose(
            ProposalRequest(
                owner_id=principal.owner_id,
                action_type=payload.action_type,
                params=payload.params,
                actor_type=ActorType.USER,
                actor_id=principal.owner_id,
                actor_label="You",
                reason=payload.reason,
                resource=payload.resource,
                confidence=1.0,
                presented_auth_level=principal.auth_level,
            )
        )
    except ActionRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": str(exc), "reasons": exc.reasons},
        ) from None

    if payload.inbox_item_id:
        try:
            services.inbox.attach_proposal(
                principal.owner_id, payload.inbox_item_id, proposal.id
            )
        except LookupError:
            pass
    payload = action_out(proposal)
    payload["summary"] = action_summary(services.db, principal.owner_id, proposal)
    return payload


@router.post("/{action_id}/approve")
def approve(
    action_id: str,
    payload: ApproveIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    presence_granted = False
    if payload.use_physical_presence:
        # Physical presence is asserted by the provider against a registered
        # device, never by the client. In this build the provider is a
        # simulation and says so in its response.
        proof = get_presence_provider().request_presence(
            principal.owner_id, principal.device_id, purpose=f"approve:{action_id}"
        )
        presence_granted = proof.granted
        if not presence_granted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": (
                        "Physical presence could not be confirmed. This action requires "
                        "confirmation at your MyBot Core."
                    ),
                    "simulated": proof.simulated,
                },
            )

    try:
        proposal = services.firewall.approve(
            principal.owner_id,
            action_id,
            approver_user_id=principal.owner_id,
            auth_level=principal.auth_level,
            session_id=principal.session.id,
            device_id=principal.device_id,
            note=payload.note,
            physical_presence=presence_granted,
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
    except ActionRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": str(exc), "reasons": exc.reasons},
        ) from None

    payload = action_out(proposal)
    payload["summary"] = action_summary(services.db, principal.owner_id, proposal)
    return payload


@router.post("/{action_id}/reject")
def reject(
    action_id: str,
    payload: RejectIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Reject a proposal. Requires no elevation -- saying no is always cheap."""
    try:
        proposal = services.firewall.reject(
            principal.owner_id,
            action_id,
            approver_user_id=principal.owner_id,
            auth_level=AuthLevel(principal.auth_level),
            note=payload.note,
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
    except ActionRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail={"message": str(exc)}
        ) from None
    return action_out(proposal)
