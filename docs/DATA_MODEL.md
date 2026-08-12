# MyBot Data Model

28 tables. Every one holding personal data inherits `OwnedMixin`, which is what
binds it to the ORM-level owner filter; a reflection test fails the build if a
new personal table forgets.

## Cross-cutting mixins

| Mixin | Adds | Why |
|---|---|---|
| `UUIDPk` | `id` (36-char string) | One textual representation everywhere — exports, audit hashes, URLs |
| `Timestamped` | `created_at`, `updated_at` | |
| `OwnedMixin` | `owner_id` FK → `users.id` ON DELETE CASCADE | Owner isolation; makes "delete my data" mechanically true |
| `Classified` | `classification` | Redaction, egress control |
| `Provenanced` | `source_kind`, `source_id`, `source_detail`, `confidence`, `inferred` | Every claim is traceable and weighted |
| `SoftDeletable` | `archived`, `archived_at`, `deleted_at` | Archive ≠ delete |

`Provenanced` is the one that shapes the product. Confidence is stored, not
inferred at read time, because the proactive engine refuses to escalate a shaky
fact into an external action and it can only do that if the number is on the row.

## Identity

**users** — the owner. Not owner-scoped; this *is* the owner. `password_hash`
(Argon2id), `strong_auth_ref` (a Vault reference, not a secret).

**devices** — phones, laptops, Cores. Untrusted by default, always.
`can_provide_physical_presence` is true only for a Core.

**auth_sessions** — server-side sessions. Stores `token_hash`, never the token.
`elevated_until` bounds a STRONG elevation; `auth_level` is recomputed from it
on every request rather than trusted.

## Life Graph

**entities** — typed nodes. Type-specific payload lives in `attributes` (JSON),
which is what lets a new entity type ship without a migration while keeping the
security-relevant columns real. `normalized_name` supports entity resolution;
`merged_into_id` records a merge without destroying the old node.

**relationships** — directed, typed edges, unique on
`(owner, from, to, type)`, with optional validity dates.

**facts** — one attributed assertion about an entity. **Never overwritten.** A
correction writes a new row and points the old one at it via
`superseded_by_id`. A user statement outranks an inference regardless of the
inference's stated confidence — the person is the authority on their own life.

## Memory

**memories** — durable, user-visible, editable, deletable. `kind` distinguishes
`FACT` / `PREFERENCE` / `RULE` / `INSTRUCTION`; `WORKING` and `CONVERSATION`
are *refused* here, because letting them in is how a memory store quietly
becomes a transcript archive. `structured` holds a machine-usable payload
(`{"appointment_time_of_day": "afternoon"}`) so deterministic code can act on a
preference rather than reading a sentence.

**chat_messages** — conversation history, retained separately and deliberately
weak as evidence.

**sources** — citable origins with a `trust` flag.

## Obligations and attention

**obligations** — broader than todos: `consequence`, `source_ids`, `recurrence`,
`recommended_action_type`, `depends_on_ids`. A todo is something you chose; an
obligation is something that happens *to* you if you do not.

**inbox_items** — Life Inbox cards. `dedupe_key` is unique per owner and is
what stops a five-minute scheduler producing 288 copies of the same deadline;
it also lets a card *update* as urgency climbs rather than being replaced.
`priority_score` is arithmetic and its breakdown is stored in `evidence`.

**daily_briefs** — one per owner per day. `facts` holds the exact source
records every line was rendered from; `coverage` records which systems were
successfully checked, which is what makes "nothing else requires your
attention" honest.

## Actions

**action_proposals** — what someone wants to change. `risk` and `base_risk` are
stored separately so tampering is visible. `derived_from_untrusted` and
`untrusted_source_ids` carry taint. `idempotency_key` is unique per owner.

**action_approvals** — a *separate table* on purpose. A proposal is what a
model produced; an approval is what a human consented to. `params_hash` binds
consent to exactly the parameters shown; `consumed_at` makes it single-use;
`invalidated_at` is how lockdown voids work in flight.

## Security

**permission_rules** — grants as data the policy engine evaluates. Writable
only by a human with STRONG auth.

**audit_events** — append-only, hash-chained per owner. Not `Timestamped`,
because an audit row has no `updated_at`: it is never updated. `sequence` is a
per-owner monotonic counter, so a gap is itself evidence.

**security_events** — noisier signals for the Security Center, kept out of the
chain so they can be queried and expired independently.

**security_states** — one row per owner: lockdown, automations, `approval_epoch`.

**credential_references** — pointers to secrets with scopes. Application code
passes these around; only the Vault turns one into anything usable.

**vault_secrets** — AES-256-GCM ciphertext. `aad` binds each blob to
`owner | ref | key_version`, so a row moved between users fails to decrypt.

**pii_tokens** — local mapping between an identifier and its placeholder,
indexed by keyed HMAC so the index is not a searchable plaintext.

## Connectors

**calendar_events**, **email_messages** — synced external data.
`injection_suspected` and `extracted` record what a deterministic classifier
found. Bodies are untrusted content and are only read through the wrapper.

**integrations** — per-provider status, exact granted scopes, `write_enabled`.

**llm_runs** — model call metadata. Note what is absent: the prompt and the
completion. Only a hash, token counts, latency, status, the maximum
classification sent, and whether untrusted content was in context.

**automation_rules**, **notifications**, **documents** — as named. `documents`
stores `extracted_fields` as `[{field, value, confidence, evidence}]`, never
bare values.

---

## Deletion vs. audit retention

The distinction that most deserves stating plainly.

**Personal content deletion is real.** `POST /api/v1/account/data/delete`
removes entities, facts, relationships, memories, obligations, inbox cards,
documents *including the encrypted files on disk*, synced calendar and email,
chat history and briefs.

**The audit chain is retained**, because it records what MyBot did and why —
references, reasons, actors, outcomes — not the content itself. Deleting it
would make the security history unverifiable, which is the one thing that lets
a user check MyBot has not been acting behind their back.

Where a derived value could leak content, it is excluded. Deleting a memory
records the id, kind and timestamp but **not** the subject line, because the
subject is derived from the content. A test asserts the deleted string appears
nowhere in the audit record.

The API response says exactly what was retained and why, rather than quietly
keeping it.

## Portability

Everything is plain columns and JSON. UUIDs are strings, timestamps are
timezone-aware UTC (a `UTCDateTime` decorator normalises SQLite, which
otherwise hands back naive datetimes and silently corrupts deadline maths).
JSON becomes JSONB on Postgres. No proprietary types, no ORM-specific
serialisation, nothing that would make leaving hard.
