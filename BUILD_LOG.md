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

## Increment 3 — encrypted backup, and a recovery design

301 tests (up from 268).

This closes the item SECURITY.md had been carrying as an open gap since the
first commit: *"Losing the master key today means losing the Vault contents."*
That sentence was honest, and it was also the reason nobody adopts local-first
software. One lost laptop and a decade of records is gone.

### The design, and the three answers it rejects

**Escrow the key with MyBot Inc.** Then MyBot Inc. can read every user's Vault
and the local-first promise is theatre. Worse, it is a single point of
compromise sitting on every user at once — the exact shape of breach this whole
architecture exists to avoid.

**Derive the backup key from the password.** A forgotten password becomes
unrecoverable data, *and* a weak password becomes the entire security of the
archive. A password change would have to re-wrap everything, at precisely the
moment you least want a complex migration running.

**No recovery.** What the previous build shipped. Honest, and unusable.

What it does instead: each backup gets a **fresh random key** sealed over the
payload, and that key is wrapped once per **recovery path** — a 24-word phrase
(Argon2id, 256 MiB, shown exactly once and stored nowhere), plus any number of
**recovery contacts** holding high-entropy material (HKDF; stretching material
that is already random only makes recovery slow). Any single path opens the
backup. None of them is us.

Two properties fell out of writing it and are worth naming, because both were
decisions rather than defaults:

**The manifest is deliberately unencrypted.** Format, date, row counts, and
which recovery paths the archive accepts — all readable with no key at all. The
person this serves is holding an unlabelled file from two years ago and needs to
know whether it is the one with their records in it *before* going to look for
the paper. It leaks nothing: the wraps are useless without the owner's material,
and the file names no owner, only a truncated hash. That hash is bound into the
AEAD context, so it is not a label somebody can edit to make an archive look
like it belongs to someone else — there is a test for exactly that.

**Argon2 parameters are recorded in the archive, not read from today's
constants.** Otherwise raising the cost as hardware improves — which we should
be free to do — would silently orphan every existing backup, and the owner
would discover it on the single day it mattered.

Shamir *m*-of-*n* splitting is deliberately **not** implemented. It is the
obvious next feature and it is exactly the clever cryptography this codebase has
a rule against hand-rolling. The wrap format reserves a `scheme` field so a
reviewed implementation drops in without a migration.

### Findings

**14. The recovery wordlist had a prefix collision.** `quarry` and `quartz`
share four letters. Caught by a test asserting no two words match on their first
four characters — which exists because the failure mode is a person squinting at
their own handwriting years later, not an attacker. Replaced with `quiver`.

**15. `parse_phrase_scheme("argon2id-")` raised `IndexError`, not
`BackupError`.** An archive is untrusted input — it arrives from a USB stick or
somebody's email — and an unhandled exception type meant a malformed one would
escape the "try the next recovery path" loop and abort recovery entirely. Now
every parse failure is a `BackupError`, a malformed wrap is skipped rather than
fatal, and there is a test that a corrupted phrase wrap does not prevent a
contact from opening the same file.

**16. The manifest's `contents` map counted scalar keys as `1`.** So
`describe` reported `"format": 1`, `"note": 1`, `"user": 1` alongside the real
row counts, burying the numbers in the one view available to someone who cannot
open the file. Collections only now.

### Decisions

**Backup is a CLI command, not an API endpoint.** An endpoint that returns a
sealed archive *and* its recovery phrase converts a stolen session token into a
permanent, offline copy of somebody's entire life. The export endpoint at least
forces an attacker to keep stealing. A backup should be a physical act performed
on your own Core.

**Restore stops at reading the archive out.** It does not merge contents back
into a live database. Which of two versions of a memory wins, and what happens
to an audit chain that came from a different machine, are questions whose wrong
answers corrupt the record *silently* — the worst failure mode available.
Recovering the data is the promise this closes; re-import is separate work that
deserves its own review.

**The export payload was extracted into `mybot_api.export`.** The route and
`mybot backup` now seal the same bytes from the same code. A backup that quietly
omits a table the export includes is the kind of divergence nobody discovers
until the day they need the backup — and the fix is one definition, not two that
drift. It stays beside the serialisers rather than moving down into
`mybot_services`, because those serialisers *are* the allowlist keeping
`password_hash` and `ciphertext` out of responses, and a second copy one layer
down would be a second copy to forget to update. There is a test asserting a
restored backup contains no such field.

**`RecoveryFailed` does not say which part was wrong.** Distinguishing "wrong
phrase" from "corrupt file" hands an attacker holding the archive a free oracle.

---

## Increment 4 — independence, and the part that grows

341 tests (up from 301).

The brief: *"create a baby that is as smart as you and will keep learning —
INDEPENDENT, each user gets their own that grows with them."*

### The constraint, stated first

Model weights cannot be copied into this repository, by me or by anyone. A
product promising "your own private frontier-level brain, forever, offline" on
consumer hardware is selling something that does not exist yet. Saying so was
the first requirement of building this honestly.

But the premise underneath the request survives the constraint, and is arguably
stronger without it:

> **The model is a rented, swappable organ. The individual is owned and
> permanent.**

What makes an installation somebody's *own* after a year is not the weights —
every user of every product shares those. It is the accumulated private record
of how one specific person actually behaves. That is buildable, ownable,
portable across model swaps, and it compounds. So that is what got built.

### Sovereign mode

`MYBOT_SOVEREIGN=true`: no model call leaves the machine, at any classification,
for any purpose.

Kept deliberately separate from the existing classification ceiling rather than
being its maximum value. A ceiling is a *graduated judgement* — "is this payload
too sensitive to send?" — and every judgement is a chance to be wrong. Sovereign
mode declines to judge. It is the setting for somebody who does not want to
audit a classifier's decisions for the rest of their life.

Enforced twice: provider selection never picks a remote provider, and the egress
guard refuses the call. Either would work today. A control with one enforcement
point is one refactor away from decorative, and this one is a product promise.
The fallback provider is itself local, so a provider outage cannot quietly
become an egress — there is a test for exactly that.

### Learning, and the wall around it

New table, `learned_preferences`, and a service with four commitments that each
rule out an easier implementation:

**Deterministic.** No model decides what MyBot has learned about you.
Observations are counted; thresholds are declared. This is not modesty dressed
as virtue — a model asked "what has this user taught you?" will confabulate a
plausible answer, and a confabulated belief *about a person* is
indistinguishable from a real one until it causes harm. Counting is auditable.

**Closed vocabulary.** A fixed table of things MyBot may conclude. An
open-ended one cannot be reviewed: you could not answer "what could this thing
decide about me?" without reading everything and guessing.

**Never authority.** This is the whole design. Each kind declares which surfaces
it may influence; `assert_never_authority` walks the table at import time and
refuses to load a kind claiming `policy`, `approval`, `risk`, `auth`,
`execution`, `audit` or `lockdown`. The sentence it exists to refuse:

> *"You approved this nine times, so I'll stop asking."*

That is a permission escalation performed by a statistic, and it looks
completely reasonable in a diff. MyBot instead says "you approved this 12 of 13
times — want to make that a rule?" and a human clicks. Verified end to end: a
simulated year of use produces the offer and creates zero permission rules.

Worth noting the symmetric case, because it was tempting: a learned **deny** is
refused too. It errs safe, and it is still learning writing authority. Today's
safe direction is tomorrow's precedent.

**Untrusted content cannot teach.** Documented as a new threat, T4a. Every
existing injection control operates on a *proposal*; none of them looks at what
the system concluded on the way there. An attacker with patience does not want
one action, they want a habit. So anything learned from content the owner did
not write is quarantined — shown, never applied — and the taint is sticky in one
direction, because otherwise the attack is one poisoned observation followed by
ordinary use laundering it clean.

### Findings

**17. The firewall could have read learned state.** The first wiring passed
`LearningService` into `ActionFirewall` directly. Nothing used it wrongly, but
the shape invited `if learned.confidence > 0.9: skip_approval()` and that line
would have looked sensible in review. Replaced with an `ObservationSink`
Protocol: one method, no return path, so authority code can report what happened
and *cannot ask* what was concluded. Same technique that keeps `mybot_llm`
unable to import the Vault — make it unexpressible, not forbidden.

**18. A learning failure could roll back an approval.** Observing runs inside
the same transaction as the approval and its audit event. An exception there
would have discarded a real decision the user had already made. Learning is an
enhancement; it now fails soft and logs, with a test that a deliberately
exploding sink cannot break an approval.

**19. Alembic autogenerate omitted its imports again.** Third time — same
`Text` and `mybot_schemas.db.types` NameError as the previous two migrations. It
is a template problem, not a one-off, and worth fixing at the source next time
somebody touches migrations.

### Decisions

**Learned state goes in the export and the backup.** It is the single most
valuable thing in the file. Entities and emails re-sync from their sources; a
decade of corrections re-syncs from nowhere. If it were missing, "your MyBot is
yours" would be false in the only moment that tests the claim. There is a test
that seals a backup, opens it, and checks the corrections survived with their
evidence counts.

**Contradictions are kept, not subtracted.** Somebody who approves a thing nine
times and rejects it once has not taught MyBot nothing — they have taught it
something with a known exception rate, and collapsing that to a boolean throws
away the part that should make MyBot cautious. The offer says "12 of 13", not
"12".

**Confidence multiplies rather than averages.** Agreement × volume × recency, so
being wrong half the time is not survivable through sheer observation count.
Tested with 250 agreements and 250 contradictions: still not a preference.

**Corrections apply immediately; inferences decay.** Making somebody repeat a
correction three times before it sticks is how an assistant becomes
infuriating. Conversely an inferred preference nobody has re-confirmed in a year
should not be insisted upon — inferences have a 90-day half-life, stated
preferences have none.

**No gamification.** No levels, no streak, no "your MyBot is 73% grown". The
growth report is a transparency feature wearing a friendly hat, and scoring it
would encourage people to feed it rather than correct it.

---

## Increment 5 — the ledger completed, OAuth, and a security-event bug

426 tests (up from 366).

### Completing the egress ledger

The ledger is the sharpest claim MyBot makes and it was incomplete in exactly
the way that would have discredited it: it counted model calls only. A sync to
Gmail sends the owner's identity and a query outward, so a ledger reading
"nothing has left this machine" while a mailbox was being polled would have
been the precise dishonesty the feature exists to prevent. **A read is egress.**

New `EgressEvent` table, unioned with `LLMRun`. Two tables rather than one is
deliberate: each is written by the code that performs the thing it records, so
neither can drift. A single "telemetry" table fed by a separate reporting path
is the design that lets a ledger quietly under-report.

### OAuth

The piece standing between "the Google adapters are code-complete" and
"somebody can connect their account". Authorization-code with PKCE, refresh
tokens in the Vault only, state bound to the owner who began the flow, exact
redirect matching, read-only first, revoke-before-delete on disconnect. Driven
against a fake authorization server, which is the right level: what needs
proving is not that httpx can POST, it is that the flow holds its properties
under login-CSRF, replay, code interception, open redirect and database theft.

### Findings

**20. Security events were destroyed by the rollback of the failures they
recorded.** The most serious finding in the build so far, and it was found by
accident — a test asserting a forged OAuth callback left a trace, which it did
not.

Events were written on the caller's session. Every event on a *failure* path
was therefore discarded when that request rolled back, and failure paths are
where the events that matter live: a non-human actor attempting to create a
permission rule (Rule 2's own evidence), an approval replay, a policy denial on
tainted input. Each records an event and then raises. The system was reliably
keeping evidence of the things that went right.

Fixed by writing security events on their own connection, committed
immediately — they are a log of attempts, not part of the unit of work being
attempted, and coupling their durability to the success of the thing they
record is backwards. Falls back to the caller's session under write contention,
and never raises, because a logging path that can fail a request lets anybody
who can provoke a write error provoke an outage. Deliberately *not* applied to
the audit chain, which is hash-linked and must be written in sequence inside
the transaction it describes.

**21. The email sync recorded egress on failure but not on success.** Caught by
a test that drives `sync_all` rather than the helper — testing the wiring, not
the unit.

**22. Ledger totals were computed from the truncated event list**, so a smaller
page size shrank the headline numbers.

**23. The Alembic template, at last.** Four consecutive migrations shipped with
a NameError because autogenerate emits fully-qualified references to the custom
type decorators without importing them. Fixed in `script.py.mako` rather than by
hand a fifth time. The first attempt failed because a literal `${imports}` in the
explanatory comment was interpolated by Mako.

### Decisions

**Sovereign mode governs models, not connectors.** Somebody running sovereign
with Gmail connected must not be told nothing left — their mail provider is
still being contacted. Conflating the two would be the ledger telling a
comfortable lie, so there is a test.

**Simulated connectors are recorded as having stayed, not omitted.** The local
count stays truthful rather than silently under-reporting what MyBot did.

**No OAuth client ships with the product.** A shipped client id would mean every
installation shared one identity at the provider.

### Cookie sessions and CSRF — two limitations that were one

Known limitations #2 and #10 were closed together, because closing either alone
makes the other worse. The session token lived in `sessionStorage`, readable by
any XSS. There were no CSRF tokens — which was *safe* precisely because auth was
bearer-only: a cross-site form post carries no `Authorization` header.

Moving the token into an httpOnly cookie takes it out of JavaScript's reach and
hands the browser the job of attaching it, which is exactly what makes CSRF
possible. One change, not two.

Layered: SameSite=Strict is the primary control and is enforced by the browser;
a double-submit CSRF token in a header is belt and braces on top, because
SameSite is a browser behaviour and browsers vary.

Three decisions inside it:

**The CSRF token is not derived from the session token.** A readable value
derived from a secret is a downgrade of that secret.

**Header only** — never a query parameter. A token in a query parameter ends up
in browser history, in server logs, and in `Referer` headers sent to third
parties.

**Bearer callers are exempt from the CSRF check**, and that is reasoning rather
than oversight. CSRF exists because browsers attach cookies automatically and
never attach an `Authorization` header automatically. Requiring a token from the
CLI would protect nothing and break every script. The exemption is keyed on how
the request authenticated, not on a flag somebody can set.

Verified in a real browser rather than only in tests: `document.cookie` shows
the CSRF token and nothing else, `sessionStorage` is empty where the token used
to live, the session cookie reports `httpOnly: true, sameSite: Strict`, a write
through the UI still succeeds, and signing out removes the cookie. Zero console
errors.

### The visual identity, redone properly

**The mark was Gmail's.** An "M" in a green rounded tile — at 64px and above it
was close enough to Gmail's mark to be a problem, which is an unfortunate thing
to resemble when the product's pitch is that it does not read your mail on
somebody else's server. Nobody had looked at it next to anything.

Six candidates were drawn and rendered at 16/24/32/64/128 and on dark before
choosing, which is the part that made the decision easy rather than a matter of
taste. Two died on meaning alone: one read as a **camera** (the worst possible
association for a privacy product) and one as a **user avatar**. Two read as an
**eject button**. Several dissolved at 16px.

The winner is a **shelter resting on a line** — the shelter because MyBot lives
in your home on your machine, the line because that is where it stops on its
own. The baseline is deliberately wider than the walls, so it reads as ground
rather than as an underline.

**The link-preview card was a text slide.** It showed the tagline on an empty
background, which told a stranger nothing about what the thing *is* — and that
image is the only one most people will ever see of MyBot. It now carries a real
screenshot of the running app, cropped past the sidebar (navigation is the least
interesting part of a product shot) and composed as two clean zones rather than
a gradient fade, because a wash over a screenshot reads as a rendering fault
rather than a design decision.

**Real screenshots, not recreations.** `scripts/capture-screens.mjs` drives the
running app and captures the actual screens; the site inlines them. A marketing
page that draws its own version of the product can drift from it, and the drift
always flatters. The two on the page are the two that make the competitive
argument: *What has left your machine* and *What it has learned about you*.

The page is now built from `www/index.src.html` via `npm run site`, which
inlines the screenshots as data URIs so the output stays a single
self-contained file.

---

## Next steps

Immediate, in order:

1. **A verified local model path.** The `LocalProvider` speaks Ollama and
   sovereign mode enforces locality, but no local model has been run against
   this build — there is no GPU here. Until that happens, sovereign mode is a
   correct control over an unproven capability, and the README says so.
2. **A UI for the growth report.** Learning is fully exposed over HTTP and has
   no screen. "Here is what I have worked out about you" is the surface that
   makes the whole thing trustworthy, and it should not be API-only.
3. Wire the Google OAuth consent flow and verify the adapters against live
   endpoints. Everything else about those integrations is ready.
4. Notification delivery transports — push and email. The model and the
   restraint logic are in place; only the transports are missing.
5. httpOnly cookie sessions, and server-sent events so the UI stops polling.
6. Scheduled backups in the daemon, and a reviewed Shamir implementation for
   the `scheme` field the wrap format already reserves.
7. Learn from more signals — which inbox cards get opened, which briefs get
   read to the end. Each new signal needs a new entry in the closed vocabulary
   and a decision about which surfaces it may touch, which is the point.

Then V0.2 as described in `docs/ROADMAP.md`.
