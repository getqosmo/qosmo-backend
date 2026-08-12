# Running MyBot on your own machine

This build was developed in a sandboxed cloud environment. Three things could
not be verified there, and all three are unblocked the moment you run it
locally:

| Blocked in the sandbox | Why | Unblocked locally |
|---|---|---|
| A real local model | No GPU; model hosts were proxy-blocked | Ollama, and a real verdict from `mybot model-check` |
| Live Google | No OAuth credentials existed | Connect a real calendar and mailbox |
| Real data | Demo seed only | Your actual life |

Nothing below is a workaround. It is the setup the product was designed for —
the sandbox was the constrained case.

---

## 1. Run it

```bash
git clone <this repo> && cd mybot
cp .env.example .env

python3 -m venv .venv && .venv/bin/pip install -e '.[dev,documents]'
.venv/bin/mybot demo          # seeds a realistic owner, prints their brief
.venv/bin/mybot serve         # API on :8000

cd apps/web && npm install && npm run dev    # :3000
```

Sign in with `alex@example.com` / `demo-password-1234`.

Everything works at this point with zero credentials and zero outbound calls.
The steps below are about replacing the simulated parts with real ones.

---

## 2. A local model — the big one

This is the step that turns sovereign mode from a correct control over an
unproven capability into a demonstrated one.

```bash
# https://ollama.com/download
ollama pull llama3.1:8b
ollama serve
```

Then point MyBot at it and **measure whether it can actually do the job**:

```bash
export MYBOT_LLM_DEFAULT_PROVIDER=local
export MYBOT_LOCAL_MODEL=llama3.1:8b

mybot model-check --provider local            # report only
mybot model-check --provider local --apply    # and act on the result
```

Expect it to fail some probes. That is the harness working, not a problem —
small models fabricate, and the whole point of `--apply` is that MyBot then
stops routing those purposes to that model and falls back to its deterministic
paths. A model that classifies well but invents phone numbers keeps
classifying.

The probe worth watching is **abstention**: asked something the records do not
answer, does the model say so, or does it produce a plausible phone number? A
model that fabricates there is not a worse assistant, it is an unsafe one.

Once you have a model you trust:

```bash
export MYBOT_SOVEREIGN=true
```

Nothing then leaves the machine, at any classification, for any purpose — and
the **What has left** screen will read zero, from the same table every other
number on it comes from.

### If your hardware is bigger

`llama3.1:70b` or a similarly-sized model will likely pass the whole suite.
Run `model-check` rather than assuming; the point of the harness is that you do
not have to trust a README, including this one.

---

## 3. Google, for real

MyBot ships with **no OAuth client**, deliberately — a shared client id would
mean every installation used one identity at the provider.

1. Google Cloud Console → new project → **APIs & Services**.
2. Enable **Google Calendar API** and **Gmail API**.
3. **OAuth consent screen**: External, add yourself as a test user. You do not
   need verification while you are the only user.
4. **Credentials → OAuth client ID → Web application**. Add this exact
   authorized redirect URI:
   ```
   http://localhost:3000/integrations/callback
   ```
   Exact — MyBot compares redirect URIs by exact string, because prefix
   matching is how open redirectors become account takeovers.
5. Put the credentials in `.env`:
   ```bash
   MYBOT_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   MYBOT_GOOGLE_CLIENT_SECRET=...
   MYBOT_OAUTH_REDIRECT_URIS=http://localhost:3000/integrations/callback
   MYBOT_INTEGRATIONS_MODE=google
   ```

Then **Connected accounts** in the app. It connects read-only; write access is
a separate grant you make later, if ever.

**What to watch for**, since this is the first time these adapters meet live
Google:

* the token exchange returning a refresh token at all (MyBot sends
  `access_type=offline` and `prompt=consent` for exactly this reason);
* field shapes in the calendar and message payloads;
* rate limits on the first full sync.

Failures here are expected and are the point of doing it. The flow itself is
tested; the adapters are not yet.

---

## 4. Your data

```bash
mybot scan            # one proactive pass
mybot brief           # today's brief
mybot worry           # what needs you
mybot learned         # what MyBot has worked out about you
```

Before you trust it with anything, look at three screens:

* **What has left** — every outbound request, including failures.
* **What it has learned** — every conclusion, with its evidence, correctable.
* **What it can do** — the permissions, answerable in seconds.

---

## 5. Back it up before you care about it

```bash
mybot backup life.mybot
```

Write the 24-word phrase down. **No copy of any key is held by anyone**, which
also means losing every recovery path loses the data. Add a recovery contact if
you want a second way in:

```bash
head -c 32 /dev/urandom > priya.key    # give this to someone you trust
mybot backup life.mybot --contact Priya:priya.key
```

---

## Production notes

If you expose this beyond localhost:

* `MYBOT_ENV=production` — makes the process refuse to start without a real
  `MYBOT_JWT_SECRET` rather than generating one, and marks cookies `Secure`.
* Set `MYBOT_CORS_ORIGINS` to your actual origin. Never `*`.
* Terminate TLS in front of it. The session cookie is `SameSite=Strict` and
  `Secure` in production, which means it will not be sent over plain HTTP at
  all.
* `MYBOT_VAULT_KEYSTORE` is `software` by default — a key file at 0600. On a
  general-purpose machine that offers no protection against an attacker who
  already has your user account, and the Security Center says so. That is the
  gap the Core hardware exists to close.

---

## What is still not done

Kept here rather than in a roadmap, because these are what you will hit:

* **No voice, no mobile app, no hardware.**
* **Money cannot move.** The registry, policy and approval flow are real; the
  adapter returns FAILED and never CONFIRMED.
* **No OCR.** Images are stored encrypted and say plainly that nothing was read
  from them.
* **Notifications are in-app only.** The restraint logic — thresholds, quiet
  hours, dedupe, a daily cap — is built; the push and email transports are not.
* **Backups are manual.** Nothing schedules them yet.
* **Rate limiting is in-process**, which is right for one machine and wrong for
  several.
