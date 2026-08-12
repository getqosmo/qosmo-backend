# Docker

Entirely optional. The fast path needs no containers:

```bash
mybot demo && mybot serve
```

Use this directory when you want the Postgres server profile:

```bash
docker compose up -d db
export MYBOT_DATABASE_URL=postgresql+psycopg://mybot:mybot-local-dev-only@localhost:5432/mybot
alembic upgrade head
```

Or the full stack:

```bash
docker compose up --build
```

Two notes:

* `MYBOT_JWT_SECRET` is empty by default. In development a key is generated and
  stored under the data volume; with `MYBOT_ENV=production` the process
  **refuses to start** without one rather than running with a predictable key.
* The `mybot-data` volume holds the Vault master key and the encrypted
  documents. Back it up. Losing it loses the Vault — see SECURITY.md §10.
