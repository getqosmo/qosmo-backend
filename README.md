# MyBot

**Your life. Running itself.**

MyBot is a local-first personal life operating system — a private chief of
staff that remembers what matters, notices what needs attention, prepares the
solution, and takes action only within permissions you have explicitly granted.

This repository contains **V0.1 (Alpha)**. It is a foundation, not a finished
product: the security architecture, the data model and the core product loop
are real and tested; the integrations are simulated by default and money cannot
move. See [What is and is not real](#what-is-and-is-not-real).

---

## Run it in two minutes

```bash
git clone <this repo> && cd mybot
cp .env.example .env

python3 -m venv .venv && .venv/bin/pip install -e '.[dev,documents]'
.venv/bin/mybot demo          # seeds a realistic owner and prints their brief
.venv/bin/mybot serve         # API on http://localhost:8000

cd apps/web && npm install && npm run dev    # http://localhost:3000
```

Sign in with `alex@example.com` / `demo-password-1234`.

No API keys. No Google account. No Docker required. The default model provider
is a deterministic local mock and the default connectors are simulated, so a
fresh clone boots, demos and passes its full test suite with zero credentials
and zero outbound network calls.

`mybot demo` prints something like:

```
  Good afternoon, Alex.
  Wednesday, August 12
  4 things need you.

    1. Electric bill is due in 2 days. Amount: $148.20. A late fee applies after the due date.
    2. Adobe Creative Cloud renews on August 14 for $79.00.
    3. “Dentist — cleaning” and “Investor meeting — Northbank Capital” overlap by 30 minutes on Friday August 14.
    4. Vehicle Registration renewal is due in 3 days. Driving with an expired registration risks a citation.

  MyBot handled:
    ✓ Surfaced 9 things worth knowing
    ✓ Tracked 4 new deadlines
    ✓ Organised 4 documents

  Nothing else requires your attention.
```

Other commands:

```bash
mybot daemon         # the proactive loop — this is what makes MyBot proactive
mybot worry          # "what do I need to worry about?" in the terminal
mybot brief          # today's brief
mybot scan           # run one proactive pass
mybot verify-audit   # verify every owner's audit hash chain
mybot backup life.mybot          # encrypted backup + a 24-word recovery phrase
mybot restore life.mybot --describe   # what is this file? (no key needed)
mybot restore life.mybot         # open it
```

`mybot backup` seals everything MyBot holds under a fresh random key, then wraps
that key once per recovery path you have — a phrase you write down, and
optionally a recovery contact. **No copy of any key is held by us**, which also
means losing every path loses the data. It is a local command rather than an
API endpoint on purpose: an endpoint that hands out a sealed archive *and* its
recovery phrase turns a stolen session token into a permanent offline copy of
your life. See [SECURITY.md §10](SECURITY.md).

`mybot daemon` is the process that runs on the Core in your home. Each pass it
syncs connectors, runs the proactive rules, evaluates your automations, and
notifies you about anything that clears the bar. It adds **no authority**: it
runs the same engines the API runs, through the same firewall, so it cannot do
anything a user-triggered scan could not.

---

## What it does

**Life Graph.** Structured entities (people, vehicles, subscriptions,
documents, providers…), typed relationships, and attributed facts. Not a pile
of embeddings: every fact carries a source, a confidence and a timestamp, and
corrections supersede rather than overwrite — so "you told me October 18, the
notice said October 14" is answerable months later.

**Life Inbox.** The home screen, not a chat box. Cards produced by a
deterministic rules engine, ranked by an arithmetic priority score whose
breakdown is stored on the card. Every card answers "Why?" with the specific
evidence behind it.

**Morning Brief.** Generated entirely from structured records by templates. No
model writes any part of it, because the brief is the one surface people read
half-awake and act on without checking.

**Ask.** Grounded chat. The important questions are answered by deterministic
code with no model in the loop; anything else goes through a tool-augmented
call whose answer is checked against the tool results before it is shown.
Every answer carries the record ids it came from.

**Action proposals.** MyBot prepares; you approve. The approval sheet shows the
subject, the before and after, the reason, who asked, the risk class and
whether it can be undone.

**Automations.** Standing instructions — *tell me three days before a
subscription renews*. Deterministic triggers over stored data; an automation
cannot be "whenever it seems important". Every one runs through the same policy
engine as everything else, so the worst a misconfigured automation produces is
a queue of proposals you decline.

**Notifications, with restraint.** A threshold, deduplication by source, quiet
hours in your timezone, and a hard daily cap. An assistant that interrupts you
about everything is worse than one that interrupts you about nothing, because
you stop reading it. None of that is a model being tasteful; it is arithmetic.

**Security Center.** A first-class surface where "what can MyBot currently do?"
is answerable in seconds.

---

## Architecture in one paragraph

Six concerns are kept in separate components, and the separation is enforced by
dependency direction rather than convention: **intelligence** (the model layer)
can propose but never authorize; **memory** and the **Life Graph** hold the
structured truth; the **policy engine** decides authority with ordinary
deterministic code; the **Action Firewall** is the single gateway every
external change passes through; the **Vault** holds credentials and is
unreachable from the reasoning layer; the **audit log** is append-only and
hash-chained. Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
      you → gateway → orchestrator → { reasoning · life graph · memory }
                                              ↓
                                      action proposal
                                              ↓
                          policy engine  (deterministic, fail-closed)
                                              ↓
                          action firewall (the only path outward)
                                              ↓
                       email · calendar · documents · future services
      ───────────────────────────────────────────────────────────────
                  vault: keys · credentials · sensitive identity
```

### The five rules

Non-negotiable, and each has tests that fail the build if the property breaks
(`tests/security/test_five_rules.py`):

1. **The AI never holds master keys.** `mybot_llm` cannot import the Vault —
   asserted by walking the package for forbidden imports.
2. **The AI can never modify its own permissions.** Rules are writable only by
   `ActorType.USER` with STRONG auth; there is no other write path.
3. **Thinking and authority are separate.** A proposal has no field for risk,
   approval or auth level, and only the Action Firewall calls an adapter.
4. **High-risk actions pass a deterministic policy engine.** It fails closed on
   any internal error and re-evaluates at approval time.
5. **Everything important is auditable.** Hash-chained, append-only, guarded by
   ORM hooks *and* database triggers.

---

## Yours, and independent

MyBot is built so that no company — including whoever ships it — is load-bearing
for it working, and so that what makes it *yours* is something you own outright.

**The model is a rented, swappable organ.** Every provider implements one narrow
interface; switching a purpose from a cloud model to one running on your own
hardware is configuration, not a code change. `MYBOT_SOVEREIGN=true` makes that
absolute: nothing leaves the machine, at any classification, for any purpose.
Enforced at provider selection *and* at the egress guard.

**What makes it yours is the part nobody else has.** Not the weights — a decade
of your corrections, your preferences, the patterns MyBot worked out by watching
what you actually do. That state is deterministic, inspectable, correctable,
portable across model swaps, and included in every encrypted backup. Entities and
emails re-sync from their sources; this re-syncs from nowhere, which is exactly
why it is the thing worth owning.

**And it grows without gaining power.** Learning shapes what MyBot suggests, how
it ranks things, how it talks to you. It can never grant a permission, raise a
risk ceiling, or approve anything — every learnable kind declares which surfaces
it may touch, and the authority surfaces are unclaimable by construction. When
MyBot notices you have approved something twelve times out of thirteen, it says
so and offers to make it a rule. **You click the button.** That sentence is the
whole design:

> *"You approved this nine times, so I'll stop asking"* is a permission
> escalation performed by a statistic. MyBot does not make it.

```bash
mybot backup life.mybot            # everything, including what it has learned
mybot model-check --provider local --apply   # prove your model is fit, and act on it
```

**And it will not pretend a weak model is fine.** `mybot model-check` measures
whether a model can do the five things MyBot actually needs — structured output,
schema constraints, abstention, grounding, format adherence — grading every
probe with ordinary code rather than an LLM judge. Fail a probe and the router
stops routing that purpose to that model, falling back to MyBot's deterministic
paths. A 3B model that classifies well but invents phone numbers gets to keep
classifying.

Honest limit: this is a per-user *individual*, not a per-user *model*. Nobody
can hand you private frontier-model weights on consumer hardware today, and a
product that claims otherwise is lying. What you own is the individual; the
intelligence is swappable underneath it, which is the part that keeps improving
without you having to migrate anything.

---

## What is and is not real

Honesty about a V0.1 matters more than a long feature list.

| Area | State |
|---|---|
| Life Graph, memory, obligations, inbox, brief | Real, tested |
| Policy engine, Action Firewall, audit chain, Vault, lockdown | Real, tested |
| Proactive daemon, automations, notifications | Real, tested |
| Rate limiting / brute-force protection | Real, tested. In-process (single-node) |
| Prompt-injection defences | Real, architectural, tested adversarially |
| Per-owner learning (corrections, preferences, growth) | Real, tested. Deterministic, never grants authority |
| Sovereign mode (nothing leaves the machine) | Real, tested. Needs a local model to be useful |
| Encrypted backup & recovery | Real, tested. Manual — nothing schedules it |
| Egress ledger (everything that left your machine) | Real, tested. Covers model calls **and** connector syncs |
| Marketing site & social kit | `www/`. `npm run social` regenerates the assets |
| Document ingestion (PDF + text) | Real. **No OCR** — images are stored and say so |
| Calendar & email connectors | **Simulated by default.** Realistic fixtures |
| Google Calendar / Gmail adapters | Code complete, **not verified against live Google**. OAuth flow is now built and tested against a fake authorization server |
| Model providers | Mock (default), Anthropic, OpenAI, local/Ollama |
| Notification delivery | In-app only. Push and email transports are not built; the model and the restraint logic are |
| Payments, taxes, government filing | **Deliberately not implemented.** The registry, policy and approval UI exist; the adapter returns FAILED, never success |
| MyBot Core hardware | Interfaces exist with software stand-ins that label themselves as simulations |

Nothing in this build fakes a completed integration. A simulated result says
"Simulated"; an unavailable capability says why.

---

## Documentation

| | |
|---|---|
| [`docs/POSITIONING.md`](docs/POSITIONING.md) | Why Alexa and Google structurally cannot ship this, and what we must not claim |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, boundaries, data flow, the decisions and why |
| [`SECURITY.md`](SECURITY.md) | Security architecture, secrets model, key management, known limitations |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Thirteen attacker scenarios: asset, path, impact, mitigation, residual risk |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | Every table, provenance, and why deletion and audit retention differ |
| [`docs/API.md`](docs/API.md) | Endpoint reference |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Setup, testing, project layout, adding an action or connector |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | V0.2 → V1 and the hardware Core |
| [`BUILD_LOG.md`](BUILD_LOG.md) | What was built, decisions made, concerns, known limitations |
| [`apps/web/public/brand/README.md`](apps/web/public/brand/README.md) | Brand assets, and how to drop in your own logo |

---

## Testing

```bash
.venv/bin/pytest                 # 268 tests
.venv/bin/pytest tests/security  # the security suite alone
.venv/bin/ruff check .
cd apps/web && npm run typecheck && npm run build
node scripts/ui-smoke.mjs        # drives a real browser end to end
```

The security suite is the interesting part. It asserts, among other things,
that a malicious email cannot produce a financial action, that one owner cannot
read another's data through the ORM or the HTTP API, that an approval cannot be
replayed or have its parameters changed after consent, that lockdown blocks
work in flight, that an automation cannot reach an action the owner has not
permitted, that password and second-factor guessing are throttled, and that the
audit chain detects tampering even with the database triggers removed.

---

## License and status

Alpha software holding sensitive personal data. Do not point it at a real
mailbox or a real bank account. MyBot is not, and will never be described as,
"unhackable" — see [`SECURITY.md`](SECURITY.md) for what it actually defends
against and what it does not.
