# MyBot Architecture

## The premise

MyBot is not a chatbot with integrations. It is a personal life operating
system with a reasoning layer bolted *on the side*, deliberately kept away from
anything that matters.

That inversion drives every structural decision below. If you build this as
"LLM + tools", the model is in the trust path for everything, and the security
model reduces to "we asked it nicely". MyBot instead treats the model as an
untrusted-but-useful component: excellent at noticing and explaining, never
permitted to authorize.

---

## Component map

```
                              ┌──────────────┐
                              │     USER     │
                              └──────┬───────┘
                     mobile · desktop · web · voice
                                     │
                            authenticated API
                                     │
                        ┌────────────▼────────────┐
                        │        GATEWAY          │  apps/api
                        │  auth · owner binding   │
                        │  request id · redaction │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │      ORCHESTRATOR       │  services/chat
                        │  intent routing · tools │
                        └────────────┬────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
      REASONING ENGINE          LIFE GRAPH             MEMORY ENGINE
      packages/llm              services/life_graph    services/memory
      mock · anthropic          entities · facts       facts · preferences
      openai · local            relationships          rules · corrections
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     │
                            ACTION PROPOSAL
                                     │
                        ┌────────────▼────────────┐
                        │      POLICY ENGINE      │  services/policy
                        │  deterministic          │
                        │  fail-closed            │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │     ACTION FIREWALL     │  services/action_firewall
                        │  the only path outward  │
                        └────────────┬────────────┘
                                     │
              ┌──────────────┬───────┴───────┬──────────────┐
              ▼              ▼               ▼              ▼
           EMAIL        CALENDAR        DOCUMENTS      FUTURE APIs
   ─────────────────────────────────────────────────────────────────
                              MYBOT VAULT                packages/security
              encryption keys · credentials · identity · PII map
   ─────────────────────────────────────────────────────────────────
                              AUDIT LOG                  services/audit
                    append-only · hash-chained · per owner
```

Alongside these, four components run outside the request cycle:

* **Proactive engine** (`services/proactive`) — deterministic rules over the
  Life Graph and synced connector data, producing Life Inbox cards.
* **Automations engine** (`services/automations`) — standing instructions with
  deterministic triggers. Routes every action through the Action Firewall with
  `ActorType.AUTOMATION`, so it is not a second path to authority.
* **Notifications** (`services/notifications`) — decides what is worth
  interrupting someone for, by arithmetic rather than judgement.
* **Brief service** (`services/brief`) — renders the morning brief and the
  "what do I need to worry about?" report from structured records.

The **daemon** (`apps/core/mybot_core/daemon.py`) drives the first three on a
schedule:

```
    per owner, per tick, each in its own transaction:
    sync connectors → proactive scan → automations → notify → housekeeping
```

It adds no authority. It calls the same engines through the same firewall, so
it cannot do anything a user-triggered scan could not — which is why a locked
owner is skipped at the top of the loop rather than processed and refused
later.

---

## The dependency graph is the security model

Boundaries enforced by import direction, not by policy documents:

```
mybot_schemas   ← everything (enums, ORM models, action registry, config)
mybot_security  ← services, api          (crypto, vault, auth, untrusted)
mybot_llm       ← services/chat only     (must NOT import mybot_security.vault)
mybot_integrations ← action_firewall only
mybot_services  ← api
mybot_api       ← nothing
```

Two of these are load-bearing and asserted by tests:

1. **`mybot_llm` cannot import the Vault.** The reasoning layer has no code
   path to key material. When the PII tokenizer genuinely needed encrypted
   storage, the fix was dependency inversion — `mybot_llm` declares a
   two-method `TokenSecretStore` protocol it owns, and the API passes a Vault
   that happens to satisfy it. The arrow still points inward.
   (`test_rule1_llm_package_cannot_reach_the_vault`)

2. **Only the Action Firewall calls `adapter.execute`.** A grep-level assertion
   over `services/` and `apps/`, so a future service that reaches an
   integration directly fails the build.
   (`test_rule3_execution_only_happens_through_the_firewall`)

---

## The action pipeline

Everything MyBot changes — internal or external — traverses this exact path.
There is no second one.

```
  proposal (from a model, a rule, or a human clicking a button)
     │
     ├─ 1. schema validation      registry-defined; extra fields rejected
     ├─ 2. risk classification    from the registry; never caller-supplied
     ├─ 3. actor capability       agents may only propose from an allowlist
     ├─ 4. taint check            untrusted-derived → never HIGH or CRITICAL
     ├─ 5. lockdown check         locked → all external mutation refused
     ├─ 6. risk floor             approval + auth requirements from risk
     ├─ 7. permission rules       may satisfy or constrain; may only tighten
     ├─ 8. confidence gate        shaky inference never runs unattended
     └─ 9. monotonicity assert    computed reqs ≥ registry floor, or refuse
     │
  human approval (single-use, expiring, bound to a hash of the parameters)
     │
  integration adapter (idempotent on the proposal's key)
     │
  outcome recording (CONFIRMED only when observed; ambiguity → UNKNOWN)
     │
  audit event (hash-chained)
```

### Design notes

**Risk is a floor, never a ceiling.** `ACTION_REGISTRY` binds each action type
to a minimum risk level. Permission rules and runtime signals may only raise
requirements. Step 9 re-checks the computed result against the floor and
refuses if anything fell below it — a bug in the engine becomes a refusal
rather than an escalation.

**Policy is re-evaluated at approval time.** A permission revoked between
proposal and approval takes effect immediately; a lockdown engaged in that
window blocks the action.

**Approvals are bound to parameters.** The approval stores
`sha256(action_type | canonical_json(params))`. If the proposal changes after
consent, the hash no longer matches and execution is refused. This is why the
web app does not construct action parameters: what the user sees and what the
approval binds must come from the same source.

**`UNKNOWN` is a real outcome.** A timeout or an ambiguous provider response
becomes `UNKNOWN`, is surfaced to the user, and is never retried
automatically. That is how money moves twice.

---

## Owner isolation

The most consequential property, and the one that fails most quietly.

Rather than relying on every query remembering its `WHERE owner_id = ?`:

* Every personal table inherits `OwnedMixin`.
* A session-wide `do_orm_execute` hook injects an owner predicate into *every*
  ORM SELECT touching an owned model, via `with_loader_criteria`.
* With no scope bound, owned models **cannot be read at all** — the query
  raises `OwnerScopeError`. System work must state a reason.

**The scope is bound to the session, not to a thread or a context variable.**
This started as a `ContextVar` and broke in a genuinely instructive way: an
ASGI framework runs middleware, dependencies and sync route handlers in
different tasks and threadpool workers, so a token set in one cannot be reset
in another. Binding to `Session.info` is both correct and conceptually right —
a unit of work belongs to one owner; that is a property of the transaction, not
of whichever thread is running it.

A reflection test walks the mapper registry and fails if a new personal table
forgets the mixin.

---

## Trust and untrusted content

Prompt injection is handled architecturally, not by asking the model nicely.

* `UntrustedContent` is a type. Constructing one requires a `source_id`.
* `PromptContext.add_untrusted()` raises `TypeError` on a bare string, so
  forgetting to wrap external text is a development-time error.
* Untrusted blocks are fenced with a per-render id derived from the content, so
  a payload cannot close its own fence.
* Taint propagates: `derived_from_untrusted` and `untrusted_source_ids` travel
  into any resulting proposal.
* The policy engine refuses HIGH and CRITICAL actions from tainted proposals at
  any confidence with any permission in place, and forces approval on
  everything else.

The system prompt still tells the model that untrusted content is data. It
measurably helps. But **the security property does not depend on the model
reading it** — the tests assert that the pipeline refuses the action, not that
the model declined to produce it.

---

## Determinism where it counts

| Decision | How it is made | Why |
|---|---|---|
| Is this action allowed? | Deterministic code | Rule 4. Phrasing must not change authority |
| Does this obligation exist? | Rules over documents and email | An invented deadline is worse than a missed one |
| Which card is most important? | Arithmetic score, breakdown stored | Ranking must be explainable and stable |
| What does the brief say? | Templates over records | The one surface read half-awake |
| Is there a calendar conflict? | Interval overlap | Trivially correct |
| How urgent does this *feel*? | — | Not modelled. Urgency derives from the score |
| What should I say back? | Model, grounded in tool results | Where models are genuinely good |

The model layer's job is noticing, explaining and phrasing. Not deciding.

---

## Data classification and egress

Every entity, fact, memory and document carries a `Classification`
(`PUBLIC` → `SECRET`). It drives three things:

1. **Redaction** — `mybot_security.redaction` runs on the way *into* logs and
   audit details, not at the sink.
2. **Egress control** — `assert_egress_allowed` refuses to send data above the
   configured ceiling (default `PERSONAL`) to a non-local model provider. Local
   providers are exempt; that is the point of on-device inference.
3. **Context minimisation** — a per-purpose field allowlist. A loan question
   gets the balance and the rate, not the name, address or SSN.

PII tokenisation replaces identifiers with stable placeholders
(`PERSON_001`, `ADDRESS_002`) before any external call. Stability matters: a
model that sees a new random token each turn cannot reason about continuity.
The mapping lives in the Vault and never leaves.

`LLMRun` records provider, model, purpose, token counts, latency, status and a
prompt *hash* — never the prompt or the completion. A table full of prompts is
a second copy of the user's life in a place nobody classified as sensitive.

---

## Audit

Per-owner hash chain. Each event hashes its own canonical content together with
the previous event's hash. Three layers guard it:

1. No API surface exposes update or delete for audit rows.
2. ORM `before_flush` hooks raise on modification or deletion.
3. Database triggers reject UPDATE and DELETE outright.

Layer 3 survives a compromised application process — the scenario the threat
model assumes. And even with the triggers dropped, `verify_chain` detects both
a modified event and a removed one, reporting the exact sequence number. Both
are tested by actually dropping the triggers.

---

## Hardware abstractions

The MyBot Core is not built. The interfaces it will implement are, with
software stand-ins that **label themselves as simulations everywhere they
surface**:

| Interface | Today | On the Core |
|---|---|---|
| `SecureKeyStore` | Key file / OS keyring / env | Secure element, non-exportable |
| `PhysicalPresenceProvider` | Simulated, reports `simulated: true` | Physical button |
| `DeviceAttestationProvider` | Trusts nothing by default | Hardware attestation |
| `LocalModelRuntime` | Reports unavailable | On-device NPU |

`HardwareKeyStore` deliberately **raises on construction** rather than
pretending. A mock that claims to be a TPM is worse than no TPM.

Note the shape of `SecureKeyStore`: it exposes `derive(purpose)`, not
`get_master_key()`. A hardware implementation physically cannot satisfy the
latter, so designing around it now avoids building an API the real device can
never provide.

---

## Repository layout

```
apps/
  api/mybot_api/          FastAPI: routers, deps, serialisers
  core/mybot_core/        Local agent runtime: CLI, demo seed
  web/                    Next.js front end
packages/
  schemas/mybot_schemas/  Enums, ORM models, action registry, config
  security/mybot_security/  Crypto, Vault, auth, redaction, untrusted, hardware
  llm/mybot_llm/          Provider abstraction, routing, minimiser, tokenizer
  integrations/mybot_integrations/  Adapter contracts, mock + Google
services/mybot_services/  audit · policy · action_firewall · life_graph ·
                          memory · obligations · inbox · proactive · brief ·
                          chat · document_ingestion · security_center
migrations/               Alembic
tests/                    unit · security · evals
docs/                     this and its neighbours
```

The spec suggested `services/audit/`; this uses
`services/mybot_services/audit/` so the import path matches the directory and
the whole tree installs as one distribution. Same boundaries, fewer packaging
sharp edges.

---

## Deliberate omissions

Things a V0.1 should *not* have, and why:

* **No autonomous execution above LOW risk.** `MAX_AUTOMATIC_RISK` is a
  constant in code, changed once by a human, not per-request by a model.
* **No vector store.** Structured retrieval first. Embeddings are a later
  addition on top, not the foundation — "when exactly does it expire, and who
  says so" is not a similarity problem.
* **No agent memory of conversations as facts.** Chat history is retained
  separately and is deliberately weak evidence; the model is asked to call a
  tool, not to remember.
* **No shell, no generic HTTP, no SQL passthrough** in the tool surface.
* **No payments.** The registry entry, the policy limits and the approval UI
  are real so the *shape* is exercised; the adapter returns FAILED.
