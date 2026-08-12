# Development

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,documents]'
cp .env.example .env

.venv/bin/mybot demo --reset     # seed a realistic owner
.venv/bin/mybot serve            # API on :8000

cd apps/web && npm install && npm run dev    # :3000
```

Zero credentials required. `MYBOT_LLM_DEFAULT_PROVIDER=mock` and
`MYBOT_INTEGRATIONS_MODE=mock` are the defaults, so the product boots, demos
and tests with no network access.

### Postgres instead of SQLite

```bash
docker compose up -d db
export MYBOT_DATABASE_URL=postgresql+psycopg://mybot:mybot@localhost:5432/mybot
.venv/bin/pip install -e '.[postgres]'
.venv/bin/alembic upgrade head
```

Both dialects are supported from the same models. SQLite is the default because
the Core is a single-user appliance and a zero-setup local database is the
right shape for that.

## Tests

```bash
.venv/bin/pytest                    # 268
.venv/bin/pytest tests/security     # the interesting ones
.venv/bin/pytest tests/evals        # AI behaviour harness
.venv/bin/ruff check .

cd apps/web && npm run typecheck && npm run build
node ../../scripts/ui-smoke.mjs     # drives a real browser end to end
```

Tests run against in-memory SQLite with the real schema, the real audit
triggers and the real owner guard. Nothing carrying a security property is
stubbed: if a test passes, the mechanism it exercises is the one that runs in
production.

The eval harness runs against the deterministic mock provider by default, so it
measures MyBot's logic rather than a model's mood. Point
`MYBOT_LLM_DEFAULT_PROVIDER` at a real provider and the same cases become a
regression suite for that model.

## Layout

```
apps/api/mybot_api/        HTTP surface only — routers, deps, serialisers
apps/core/mybot_core/      Local agent runtime: CLI, demo seed
apps/web/                  Next.js
packages/schemas/          Enums, ORM models, action registry, config
packages/security/         Crypto, Vault, auth, redaction, untrusted, hardware
packages/llm/              Providers, routing, minimiser, tokenizer
packages/integrations/     Adapter contracts, mock + Google
services/mybot_services/   One package per bounded context
tests/{unit,security,evals}
```

Import direction is the security model. `mybot_llm` must never import
`mybot_security.vault`; a test enforces it.

## Adding an action type

1. Add a parameter model and an `ActionSpec` to
   `packages/schemas/mybot_schemas/actions.py`. Risk is a **floor**.
2. If a model should be able to propose it, add it to `AGENT_PROPOSABLE` —
   think hard first.
3. Implement it in an adapter under `packages/integrations/`, registering the
   action in `supported_actions`. Make it idempotent on
   `ctx.idempotency_key`, and return `UNKNOWN` for anything ambiguous.
4. Add it to the registry in `build_default_registry`.
5. Write the policy test *before* the happy path.

Anything at HIGH or above is automatically added to `UNTRUSTED_FORBIDDEN` and
requires a standing permission rule.

## Adding a connector

Implement `CalendarConnector` / `EmailConnector` for reads and
`IntegrationAdapter` for writes — they are separate contracts on purpose.
Everything a reader returns is untrusted; wrap bodies in `UntrustedContent`
with a `source_id`. Never hold a long-lived credential: take a Vault grant and
exchange it at the boundary.

## Adding a proactive rule

Add a method to `ProactiveEngine`, emit a `CardDraft` with a stable
`dedupe_key`, a `rule_id`, cited `source_ids`, a `reason` that answers "Why?",
and complete `possible_actions` including their parameters. Actions MyBot
cannot construct should be marked `available: false` with a plain reason
rather than offered and then failing.

## Running the proactive loop

```bash
mybot daemon              # runs until interrupted
mybot daemon --once       # a single pass, useful in a test loop
mybot daemon --interval 30
```

This is the process that makes MyBot proactive rather than
reactive-when-opened. It adds no authority: same engines, same firewall.

## Backup and restore

```bash
mybot backup life.mybot                       # + a 24-word phrase, shown once
mybot backup life.mybot --contact Priya:priya.key   # add a recovery contact
mybot restore life.mybot --describe           # what is this? (no key needed)
mybot restore life.mybot                      # prompts for the phrase
mybot restore life.mybot --contact Priya:priya.key --output out.json
```

`--owner ID|EMAIL` is required when the Core has more than one owner; with one
it is inferred.

A recovery contact's file is raw high-entropy material — 32 bytes from
`/dev/urandom` is the intended shape, held by the person you would call if you
lost the paper. It is stretched with HKDF rather than Argon2, because material
that is already random gains nothing from stretching except a slow recovery.

Backups round-trip through the *same* payload builder as `GET
/api/v1/account/export` (`mybot_api.export`). If you add a table, add it there
and both get it.

The real Argon2 parameters are 256 MiB per derivation. `tests/security/
test_backup.py` patches them down at module level and relies on the archive
recording what it was made with — do not lower the production constants to make
a test faster; there is a test asserting you have not.

## Working on the frontend

`npm run dev` for iteration.

If you use `next start`, **restart it after every build**. Rebuilding while it
runs leaves it serving dead chunk references: the page renders from static HTML
and never hydrates, so the UI looks correct and no button works. This cost real
debugging time twice during development.

## Brand assets

```bash
npm run brand             # rasterise the SVGs into PNG icons and the OG card
```

See `apps/web/public/brand/README.md` for dropping in your own artwork.

## Conventions

* Deterministic code decides; models explain. If you find yourself asking a
  model whether something is allowed, stop.
* Every user-visible claim needs a source id.
* Ambiguity resolves to refusal.
* Never report success you did not observe.
* Redact on the way in, not at the sink.
