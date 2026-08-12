# Build Log

A running record of what was built, what was decided and why, what was found,
and what is knowingly incomplete.

---

## V0.1 — Alpha

### Starting state

The repository contained a single Vercel serverless function proxying the
Anthropic API (`api/ask.js`), an empty README and an empty `vercel.json`.
Effectively a blank slate. That file has been removed; nothing was carried
forward.

### What was completed

**Foundations**
- Monorepo: `apps/{api,core,web}`, `packages/{schemas,security,llm,integrations}`,
  `services/mybot_services/*`, `migrations`, `tests`, `docs`, `docker`.
- 28-table schema, SQLAlchemy 2.0, portable across SQLite and PostgreSQL.
- Alembic migration including the audit-immutability triggers, verified up and
  down on SQLite.

**Security core**
- Owner isolation enforced at the ORM layer, bound to the database session.
- Deterministic policy engine with a nine-step evaluation order, fail-closed on
  any internal error, monotonicity assertion against the registry floor.
- Action Firewall as the single gateway to every mutation.
- Hash-chained append-only audit, guarded by ORM hooks *and* database triggers.
- Vault: AES-256-GCM, HKDF-derived purpose subkeys, AAD binding to owner and
  ref, incremental key rotation, capability-style `authorize_request`.
- Auth: Argon2id, server-side sessions, time-boxed STRONG elevation, TOTP
  second factor, no user enumeration.
- Lockdown: blocks external mutation, voids in-flight approvals, disables
  automations, downgrades elevated sessions, bumps the approval epoch.

**Product**
- Life Graph with entity resolution, superseding facts and typed relationships.
- Tiered memory with structured preference extraction.
- Obligations with recurrence, consequence and provenance.
- Deterministic proactive engine: 10 rules, stable dedupe keys, cited evidence.
- Arithmetic priority scoring with a stored breakdown.
- Morning brief, entirely template-rendered.
- Grounded chat: deterministic intents first, model fallback with a grounding
  check.
- Document ingestion with per-field confidence and evidence, encrypted at rest.
- Mock connectors; Google Calendar and Gmail adapters written but unverified.
- Next.js front end: seven screens, a real approval sheet, a Security Center.

**Verification**
- 238 tests: 108 security (including 28 red-team), 93 unit, 37 evals.
- `ruff` clean. `tsc --noEmit` clean. Production build clean.
- Full browser walkthrough of every screen, sign-in through approval.

---

## Decisions

**Owner scope bound to the session, not a context variable.**
The first implementation used a `ContextVar`, which broke in an instructive
way: an ASGI framework runs middleware, dependencies and sync route handlers in
different tasks and threadpool workers, so a token set in one cannot be reset in
another. Binding to `Session.info` is both correct and conceptually right — a
unit of work belongs to one owner; that is a property of the transaction, not
of whichever thread happens to run it.

**SQLite as the default, Postgres supported.**
The spec suggested Postgres. The Core is a single-user appliance in someone's
home, where a zero-setup embedded database is the right shape and `mybot demo`
working with no Docker matters more than server ergonomics. Both dialects run
from the same models and the same migration.

**The mock model provider is the default, and it is not a toy.**
It runs in-process, needs no key and no network, and constructs schema-valid
but *empty* objects rather than plausible fabrications. That makes the
grounding tests measure MyBot's logic rather than a model's luck, and it means
the entire security pipeline — including the reasoning layer — is exercised
deterministically in CI.

**The morning brief has no model in it at all.**
It is the one surface people read half-awake and act on without checking. A
model that can phrase it can invent an obligation. The hook for optional
narration exists and is off.

**HIGH and CRITICAL require a standing permission *and* an approval.**
Clicking "approve" on a $4,820 payment is not sufficient if the owner never
granted payment authority. Approval proves presence; the rule proves intent.

**Payments are registered but deliberately unimplemented.**
The registry entry, the policy limits, the approval UI and the audit trail are
all real, so the shape is exercised end to end. The adapter returns FAILED and
never CONFIRMED. A plausible-looking stub is how something gets wired up by
accident.

**Action parameters are built by the server.**
Originally the browser assembled them (a new appointment time, a draft body).
Since an approval binds a hash of exactly those values, letting the client
build them is both a correctness problem and a spoofing vector. The proactive
engine now computes complete parameters and the card carries them ready to
submit.

**Directory layout deviates slightly from the spec.**
`services/mybot_services/audit/` rather than `services/audit/`, so the import
path matches the directory and the whole tree installs as one distribution.
Same boundaries.

---

## Findings from the internal red-team pass

Each of these was a real defect, found by a test written to attack the system,
and fixed at the source rather than in the test.

**1. The LLM package could import the Vault.** *(Rule 1 violation)*
The PII tokenizer took a `Vault` directly, which meant `mybot_llm` had an
import path to key material. Fixed by dependency inversion: `mybot_llm` now
declares a two-method `TokenSecretStore` protocol it owns, and the API passes
an adapter. There is no read method — the tokenizer writes the mapping and
never needs it back. The arrow points inward, and the test that caught it now
guards it.

**2. A malformed id in a URL produced a 500 with SQL in the log.**
`UUIDStr` raised inside the type decorator when a non-UUID was bound. That
turned `GET /actions/<garbage>` into an internal error, leaked a SQL statement
into the log, and let a prober distinguish a malformed id from a missing one.
Non-UUID values are now passed through — they match no row, which is the
correct answer.

**3. The Security Center leaked the vault key file path.**
`SoftwareKeyStore.describe()` returned the absolute path of the master key
file, which is surfaced over the API. Free reconnaissance for an attacker and
useless to the owner. Removed; the backend and its honest caveat remain.

**4. Deleting a memory left a fragment of it in the audit log.**
The deletion event recorded the memory's `subject`, which is *derived from the
content*. So "delete this" left a readable trace of what was deleted. Now only
the id, kind and timestamp are recorded, and a test asserts the deleted string
appears nowhere in the audit record.

**5. An injection pattern gap.**
`</UNTRUSTED_00000000>` and an inline `SYSTEM:` both evaded the scanner —
the tag pattern did not allow digits, and system impersonation only matched at
line start. Both patterns widened. (Detection is a signal, not a control; the
architectural defences applied regardless. Still worth fixing.)

**6. The grounding check rejected correct answers.**
`$148.20` did not match a corpus value serialised as `148.2`, so a *true*
statement was being suppressed. Amounts are now compared numerically and dates
as dates. Suppressing a correct answer is its own kind of failure.

**7. The same deadline appeared twice on the home screen.**
A document expiry produced both an obligation card and a document card, worded
differently — which reads as two problems. The document rule now skips
documents already tracked by an obligation.

**8. An insurance declaration was classified as a vehicle registration.**
Both contain a VIN, and the registration signature matched first, so two
documents merged into one entity with two conflicting "expiry" dates. Signature
ordering fixed and the registration markers made specific.

**9. The scheduler proposed a Saturday dentist appointment.**
Technically a free slot; useless as a suggestion. `find_free_slot` now skips
weekends by default.

**10. The approval sheet showed a raw event id.**
"Currently: evt-dentist" instead of "Dentist — cleaning, Friday 14 August, 2:00
PM". The human-readable before/after is now derived server-side from the
referenced records, so what is displayed and what the approval binds come from
the same source.

**11. Next.js shipped with a published CVE.**
The scaffolded version carried a known vulnerability. Upgraded before writing
any UI. For a product whose entire premise is trust, shipping a
known-vulnerable framework would be indefensible.

---

## Security concerns carried forward

Stated here rather than buried, and expanded in `SECURITY.md` §9.

1. **Software keystore.** On a general-purpose OS this offers no protection
   against an attacker who already has the user's account. This is the gap the
   Core hardware exists to close. It is stated in the UI, not hidden.
2. **Personal content is not encrypted at rest** beyond disk-level encryption.
   A stolen database file discloses the Life Graph. Per-record encryption has a
   real cost in queryability and is future work.
3. **Session token in `sessionStorage`** — XSS-readable. httpOnly cookies are
   the production answer.
4. **No rate limiting** on authentication. Failures are recorded but not
   throttled.
5. **No recovery path for a lost master key.** Deliberate: the alternative is
   an escrow that becomes the single point of compromise. The sharded design is
   roadmap work and should not be improvised.
6. **Supply chain.** An in-process compromise defeats in-process controls. The
   dependency set is deliberately small and the audit triggers survive at the
   storage layer, but pinning, vendoring and SBOM are not done.
7. **Injection detection is pattern-based** and will be evaded by novel
   phrasings. It changes nothing about safety, because the controls apply to
   all untrusted content regardless.

---

## Known limitations

- **No OCR.** Images are stored encrypted and explicitly report that nothing
  was read from them.
- **Google adapters unverified against live endpoints.** Complete code paths
  targeting the real APIs, but no credentials existed in this build and the
  OAuth consent flow is not wired. `MYBOT_INTEGRATIONS_MODE` defaults to `mock`
  for exactly this reason.
- **Payments, taxes, government filing** are interface only, by design.
- **Chat history retention is not enforced.** Stored separately from durable
  memory, but no expiry job runs.
- **No background scheduler process.** The proactive engine runs on request and
  via `mybot scan`; a daemon is trivial to add and was not needed for V0.1.
- **Entity resolution is conservative.** It will leave duplicates rather than
  risk merging two people who share a surname. Merging is available and
  deliberate.
- **Single-node.** No HA, no replication, no automated backups.

---

## Definition of done — V0.1

| Requirement | State |
|---|---|
| Launch locally | `mybot demo && mybot serve` + `npm run dev` |
| Create / log into a user | Registration and login through the API and UI |
| "Good morning. N things need you." | Home screen, from the deterministic brief |
| Inspect inbox, graph, obligations, documents, memories, permissions, audit | All seven screens |
| "What do I need to worry about?" answered from stored data | Deterministic endpoint, no model |
| "Remember that I prefer afternoon appointments" | Stored, structured, and *acted on* by the scheduler |
| Calendar conflict → action proposal → approve/reject | Verified in a real browser |
| A dangerous action cannot bypass the policy engine | 28 red-team tests |
| A malicious email cannot trigger a privileged action | End-to-end test asserting zero financial actions |
| Lockdown blocks external mutations | Tested via services and HTTP |
| Actions are audited | Hash-chained; tampering detected with triggers removed |
| Tests | 238 passing |
| Architecture and security documentation | 9,400 words across 8 documents |
| Frontend looks like a credible consumer product | Verified visually, all seven screens |

---

## Increment 2 — proactive, automations, brand

### What was completed

**Brand system.** An SVG mark that reads as an *M* and as a roofline (MyBot
lives in your home) with a dot for the Core. Rendered inline as a React
component rather than loaded as an image, so it inherits `currentColor` and
adapts to light and dark without shipping two files. Favicon, PWA manifest,
Apple touch icon and a link-preview card, rasterised from the SVGs by
`scripts/render-brand.mjs` using the Chromium that Playwright already provides
rather than adding an image dependency. `apps/web/public/brand/README.md`
documents the drop-in path for replacement artwork.

*Note:* the message said ChatGPT had made logos, but no files were attached or
present in the repository. The slot is built and documented; dropping in the
real files is a five-minute change with no code involved.

**Rate limiting.** Closes the gap earlier builds listed as a known weakness.
Cost-shaped token buckets: five sign-in attempts a minute, five second-factor
attempts per *five* minutes (a six-digit code is a small space), generous
limits on reads. Keyed by owner once identity is known and by a *hashed* client
address before that — a rate limiter should not quietly become a record of who
connected from where. A correct password clears the bucket. Deliberately fails
*open*, which is the opposite of the rule everywhere else in MyBot: a limiter
is an availability control, and if it breaks the right answer is to let the
request through and let the real authorization checks work, not to lock
somebody out of their own life.

**The proactive daemon.** Until now the proactive engine only ran when somebody
opened the app, which made "MyBot notices things" quietly untrue — it noticed
things *while you were looking*. `mybot daemon` is the process that runs on the
Core. Each owner is processed in its own transaction so one failure does not
stop the others; locked owners are skipped before any outbound call; SIGTERM is
handled so a container stop is graceful. It adds **no authority** — same
engines, same firewall — and a test asserts that by giving it the most
permissive possible setup and confirming nothing executes.

**Automations.** Deterministic triggers over stored data; an automation cannot
be "whenever it seems important". Every one runs through the Action Firewall
with `ActorType.AUTOMATION`, so the worst a misconfigured automation produces
is a queue of proposals the owner declines. Trigger types are a fixed list,
because a trigger is a query and arbitrary user-supplied queries are a bad
idea.

**Notifications.** The table had existed since the first commit with nothing
writing to it. Now: a priority threshold, deduplication by source, quiet hours
in the owner's own timezone, and a hard daily cap. An assistant that interrupts
you about everything is worse than one that interrupts you about nothing.

### Findings

**12. Notifications had no dedupe key, and `notify()` silently ignored its
`source` argument.** So an automation and a proactive rule that noticed the
same subscription renewal both fired — visible immediately in the first real
daemon run, which produced five notifications where four were correct. Fixed
properly: a `dedupe_key` column with a per-owner unique constraint, keyed on
the underlying *source record* so both routes agree on what "the same thing"
means. Second migration, which also demonstrated the migration path works for
a change rather than only for initial creation.

**13. Next.js `next start` serves dead chunk references after a rebuild.** Not
a MyBot bug, but it cost real debugging time twice: the page renders (static
HTML) and never hydrates, so the UI looks fine and no button works. Noted in
`docs/DEVELOPMENT.md`.

### Decisions

**The daemon adds no authority, deliberately.** It would have been easy to let
a background process execute LOW-risk actions directly, and it would have been
wrong: the whole security model rests on there being exactly one path outward.
The daemon calls the same firewall as a user request.

**Notification restraint is arithmetic, not taste.** Thresholds, dedupe keys,
quiet hours and a daily cap — no model decides what is worth interrupting
someone for. A model asked to be tasteful is a model that will occasionally be
tasteless at 3am.

**Rate limiting fails open.** Stated again because it is the one place MyBot
deliberately breaks its own fail-closed rule, and that asymmetry should be
obvious to whoever reads this next.

**In-process limiter rather than Redis.** The Core is a single-node appliance
in someone's home; a Redis dependency there would be absurd. `RateLimitStore`
is an interface with an obvious second implementation for a multi-node
deployment.

---

## Next steps

Immediate, in order:

1. Wire the Google OAuth consent flow and verify the adapters against live
   endpoints. Everything else about those integrations is ready.
2. Notification delivery transports — push and email. The model and the
   restraint logic are in place; only the transports are missing.
3. httpOnly cookie sessions, and server-sent events so the UI stops polling.
4. Local model support via Ollama, which is what makes `PERSONAL`+ context
   viable without leaving the machine.
5. Encrypted backup with a real recovery design.

Then V0.2 as described in `docs/ROADMAP.md`.
