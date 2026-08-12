# MyBot API

Base: `http://localhost:8000`. All `/api/v1/*` endpoints except auth require
`Authorization: Bearer <token>`.

Interactive docs at `/docs` (disabled in production).

## Conventions

* **404, not 403, for another owner's resource.** Confirming existence leaks it.
* **Refusals explain themselves.** A blocked action returns
  `{"detail": {"message": "...", "reasons": [...]}}` so the UI can say *why*.
* **No secret is ever returned.** Responses are built by explicit serialisers
  with per-resource allowlists, so a new sensitive column is invisible until
  somebody consciously exposes it.
* Every response carries `x-request-id`, which appears in logs and audit events.

## Auth

| | |
|---|---|
| `POST /api/v1/auth/register` | Create the owner. Returns a token and, in development only, the second-factor secret |
| `POST /api/v1/auth/login` | Identical error for unknown email and wrong password |
| `POST /api/v1/auth/elevate` | Prove the second factor → STRONG for a bounded window |
| `POST /api/v1/auth/logout` | Revokes the session server-side |
| `GET /api/v1/auth/me` | Current identity and *effective* auth level |

## Today, inbox, brief

| | |
|---|---|
| `GET /api/v1/today` | Syncs, scans, and returns brief + cards + `coverage` |
| `GET /api/v1/brief?date=YYYY-MM-DD` | Today's brief, or a stored one |
| `GET /api/v1/worry` | "What do I need to worry about?" — fully deterministic |
| `GET /api/v1/inbox` | `state`, `category`, `limit`, `refresh` |
| `POST /api/v1/inbox/{id}/resolve` · `/dismiss` · `/snooze` | |

`coverage` reports which systems were successfully checked. It is what backs
the rule that "nothing else requires your attention" is only printed when
everything was actually consulted.

## Life Graph, memory, obligations

| | |
|---|---|
| `GET /api/v1/entities` | `type`, `q`, `include_archived` |
| `GET /api/v1/entities/{id}` | With current facts and relationships |
| `POST` · `PATCH` · `DELETE /api/v1/entities[/{id}]` | DELETE archives |
| `GET /api/v1/entities/{id}/facts/{key}/history` | Every version, including superseded |
| `GET` · `POST /api/v1/memory` | |
| `POST /api/v1/memory/{id}/correct` | Supersedes; attributed to the user |
| `DELETE /api/v1/memory/{id}` | Real deletion |
| `GET` · `POST /api/v1/obligations` | |
| `POST /api/v1/obligations/{id}/complete` | Rolls a recurring one forward |

## Actions

| | |
|---|---|
| `GET /api/v1/actions` | `status`, `limit` |
| `GET /api/v1/actions/registry` | The action catalogue and its fixed risk levels — read-only |
| `GET /api/v1/actions/{id}` | Includes `summary` (server-derived) and the audit trail |
| `POST /api/v1/actions` | Create a proposal. **Cannot set risk, approval or auth level** |
| `POST /api/v1/actions/{id}/approve` | Re-evaluates policy; single-use; params-bound |
| `POST /api/v1/actions/{id}/reject` | Requires no elevation |

`summary` is computed from the proposal's parameters and the records they
reference — never supplied by the client. Since the approval binds a hash of
the parameters, a client-supplied display could show one thing and do another.

## Security

| | |
|---|---|
| `GET /api/v1/security` | Everything needed to answer "what can MyBot do?" |
| `GET /api/v1/security/events` | |
| `GET` · `POST /api/v1/security/permissions` | POST requires **STRONG** |
| `DELETE /api/v1/security/permissions/{id}` | No elevation — revoking is always cheap |
| `POST /api/v1/security/lockdown` | Any valid session |
| `POST /api/v1/security/unlock` | Requires **STRONG** |
| `POST` · `DELETE /api/v1/security/devices[/{id}]` | |
| `GET /api/v1/audit` | `limit`, `offset`, `event_type`, `resource_id` |
| `GET /api/v1/audit/verify` | Recompute the hash chain |

There is no endpoint that updates or deletes an audit event. There is no code
path either.

## Chat and documents

| | |
|---|---|
| `POST /api/v1/chat` | Returns `citations`, `grounded_only`, `unavailable` |
| `GET /api/v1/chat/tools` | The complete tool surface, published so the capability boundary is inspectable |
| `GET /api/v1/chat/{conversation_id}/history` | |
| `GET` · `POST /api/v1/documents` | Multipart upload, 25 MB limit |

## Integrations

| | |
|---|---|
| `GET /api/v1/integrations` | |
| `POST /api/v1/integrations/{provider}/connect` | **501** — says plainly what exists and what does not |
| `POST /api/v1/integrations/sync` | |

## Ownership

| | |
|---|---|
| `GET /api/v1/account/export` | Complete JSON: graph, memories, obligations, documents, actions, audit |
| `POST /api/v1/account/data/delete` | Requires STRONG and the phrase `DELETE MY DATA` |
