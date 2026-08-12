# MyBot Threat Model

Thirteen scenarios. For each: the asset, the attack path, the impact, what
mitigates it today, and the residual risk that remains.

Residual risk is stated honestly. A threat model where everything is "fully
mitigated" is a threat model nobody used.

**Assets, in rough order of consequence**

| | Asset | Why it matters |
|---|---|---|
| A1 | Vault contents | Credentials to the user's accounts |
| A2 | Identity documents | Passport, licence — enable impersonation |
| A3 | Financial authority | The ability to move money |
| A4 | Life Graph | A complete map of a person's life |
| A5 | Email and calendar | Contents plus the ability to act as the user |
| A6 | Audit history | The only record of what happened |
| A7 | Permission rules | The definition of what MyBot may do |
| A8 | Availability | MyBot failing safe still means failing |

---

## T1 — External attacker, network

**Path.** Internet-facing API. Credential stuffing, token theft, endpoint
probing, injection through request bodies.

**Impact.** Full account takeover → A1–A5.

**Mitigations.** Token-bucket rate limiting on authentication: five sign-in
attempts per minute per address *and* per email, five second-factor attempts
per five minutes. Argon2id passwords with a 12-character minimum. Random
256-bit session tokens stored only as hashes. Identical errors and equalised
timing for unknown-email and wrong-password. Server-side sessions, revocable.
STRONG elevation required for high-risk operations and expiring on a timer. All
input validated by Pydantic; the ORM parameterises everything. Explicit CORS
allowlist, never `*`. Unhandled exceptions return an opaque message plus a
request id.

**Residual.** The limiter is in-process, so a multi-node deployment needs a
shared store before the limits mean anything across replicas. There is no
permanent account lockout, deliberately: lockout is a denial-of-service vector
against the legitimate owner, and throttling achieves the same end without
handing an attacker the ability to lock somebody out of their own life. A
stolen valid token works until it expires or the session is revoked.

---

## T2 — Compromised integration (Google, a future provider)

**Path.** The provider is breached, or a malicious update starts returning
attacker-chosen data.

**Impact.** Poisoned calendar and email data (A5); attempts to drive MyBot into
harmful actions.

**Mitigations.** Everything fetched is untrusted by construction. Least
privilege: read scopes at connect, write scopes as a separate grant. Adapters
receive short-lived Vault grants, not refresh tokens. Nothing a connector
returns can produce a HIGH or CRITICAL action. Read-only by default per
provider, shown in the Security Center.

**Residual.** Poisoned *read* data can mislead the user through the inbox — a
fabricated "your registration expires tomorrow". Provenance is shown on every
card, which makes the lie inspectable but not impossible.

---

## T3 — Compromised LLM provider

**Path.** The model vendor is breached or turns hostile: reads prompts,
returns crafted completions.

**Impact.** Disclosure of whatever context left the machine (A4); attempts to
induce harmful actions.

**Mitigations.** Context minimisation drops every field the purpose does not
need. PII tokenisation replaces names, addresses, emails, phones and government
ids with stable placeholders; the mapping never leaves. `assert_egress_allowed`
refuses to send data above the configured ceiling (default `PERSONAL`) to a
non-local provider. Model output is inert data: structured outputs are schema
validated and rejected on mismatch; free text is grounding-checked against tool
results. Nothing the model returns can authorise anything. Prompts are not
persisted — only hashes.

**Residual.** Tokenised context still carries structure and timing that could
be correlated by a determined adversary. The real fix is local inference, which
is why `LocalModelRuntime` exists.

---

## T4 — Malicious prompt injection

**Path.** Anyone emails the user. The body reaches a model.

**Impact.** If unmitigated: MyBot acting on an attacker's instructions — the
highest-severity scenario in this document.

**Mitigations.** Eight layers (SECURITY.md §6), of which seven do not depend on
the model behaving. Type-level wrapping; content-derived fences; taint
propagation into proposals; HIGH and CRITICAL refused outright from tainted
input at any confidence with any permission; MEDIUM forced to human approval;
money actions absent from the agent-proposable set entirely; the approval sheet
warning explicitly when a proposal derives from external content.

**Residual.** A sufficiently persuasive injection can still cause a *plausible
but wrong* LOW-risk internal action — a mis-filed document, a spurious
obligation — or waste the user's attention. All of it is reversible and
audited.

---

## T5 — LLM behaves incorrectly (no attacker)

**Path.** Hallucinated deadline, misread amount, confidently wrong extraction.

**Impact.** False obligations, wrong advice, eroded trust (A4, A8).

**Mitigations.** Obligations are established by deterministic extraction, not
by a model. Every extracted field stores value, confidence and the literal text
it came from. Low-confidence values never become deadlines. The morning brief
is template-rendered from records. Chat answers are grounding-checked. The
mock provider — the default — constructs schema-valid but *empty* objects
rather than plausible fabrications, so grounding tests measure MyBot's logic
rather than a model's luck.

**Residual.** Deterministic extraction has its own error modes: it will miss
unusual document layouts. A missed deadline is the failure mode chosen
deliberately over a fabricated one.

---

## T6 — Malicious insider at MyBot Inc.

**Path.** An employee with production access reads or alters user data.

**Impact.** Mass disclosure (A1–A5) or covered-up tampering (A6).

**Mitigations.** **Local-first is the primary control**: the database, the
documents and the Vault key live on the user's machine, so there is no central
store to raid. Vault contents are ciphertext whose key is not in the database.
Audit is hash-chained and append-only at the storage layer, so alterations are
detectable after the fact.

**Residual.** Substantial for any future cloud component. Whoever operates a
sync service can see what it holds unless it is genuinely zero-knowledge —
which is why zero-knowledge backup is a roadmap item and not a claim today.

---

## T7 — Stolen or lost device

**Path.** Laptop or phone taken, unlocked or with the disk readable.

**Impact.** Session access; on the primary machine, potentially the Vault key
(A1).

**Mitigations.** Lockdown from any other session: blocks external actions,
voids outstanding approvals, disables automations, downgrades every elevated
session, bumps the approval epoch. Per-device revocation kills that device's
sessions immediately. Elevation expires. Documents are encrypted at rest.
Unlocking requires STRONG — deliberately harder than locking.

**Residual.** **Significant.** A software keystore on a stolen, unlocked
machine yields the master key. This is the gap the Core hardware exists to
close, and it is stated in the UI rather than hidden.

*Availability* is now separately covered: an encrypted backup is sealed under
its own key, not the master key, so a device lost with no chance to lock it
still loses the attacker nothing from the archive — and loses the owner nothing
either, provided a backup exists.

---

## T8 — Database breach

**Path.** Database file copied, or file access on the host.

**Impact.** Personal records (A4, A5). Secrets only if the key is also taken.

**Mitigations.** Vault contents are AES-256-GCM ciphertext with AAD binding to
owner and ref; the key lives in the keystore, not the database. Passwords are
Argon2id. Session tokens are stored as hashes and are useless. Identifiers
extracted from documents are masked in queryable columns. Tampering with audit
rows is detectable.

**Residual.** **Personal content in the main tables is not encrypted at rest
beyond disk-level encryption.** Entities, facts, obligations and email metadata
are readable from a stolen database file. Per-record encryption is future work
with a real cost in queryability, and pretending otherwise would be dishonest.

**Note the asymmetry with a stolen `mybot backup` archive**, which is a
different and much better case: an archive is sealed under a key that exists
nowhere but in the owner's phrase and their recovery contacts' material. Whoever
holds the file learns the format, the date, the row counts, and a truncated
owner hash — and nothing else. This is the one artefact where "exfiltrated" is
not a disclosure, and it is why backup is a local command rather than something
the API will hand out (SECURITY.md §10).

---

## T9 — Session hijacking / XSS

**Path.** XSS in the web app, or a token captured in transit.

**Impact.** Actions as the user within that session's auth level (A5).

**Mitigations.** React escapes by default and the app renders no
`dangerouslySetInnerHTML`. `sessionStorage` rather than `localStorage`. Short
token lifetime; server-side revocation. HIGH and CRITICAL still require STRONG,
which a hijacked BASIC session does not have. Every action is audited and
visible in the Security Center.

**Residual.** A token in `sessionStorage` is XSS-readable. httpOnly cookies are
the correct production answer and are listed as a known limitation.

---

## T10 — Credential theft (the user's password)

**Path.** Reuse, phishing, keylogger.

**Impact.** Login (A4, A5); not immediately A1 or A3.

**Mitigations.** Password alone grants only BASIC. Permissions, unlock and
HIGH-risk approvals all require STRONG. Sessions and devices are visible and
revocable. Login events are recorded and surfaced.

**Residual.** BASIC is enough to read the Life Graph and to approve MEDIUM
actions such as sending an email. That is a deliberate usability trade-off,
stated rather than hidden.

---

## T11 — Malicious plugin (future)

**Path.** A third-party skill requests broad permissions or behaves
maliciously.

**Impact.** Whatever it was granted (A4, A5).

**Mitigations today.** **There is no plugin execution.** The manifest shape is
designed (declared permissions, scoped to specific fields and limits) and
nothing loads third-party code.

**Residual.** Entirely future work. Any plugin runtime must be sandboxed, its
permissions must flow through the same policy engine, and it must never receive
raw credentials.

---

## T12 — Supply-chain compromise

**Path.** A malicious version of a Python or npm dependency.

**Impact.** Arbitrary code in-process → potentially everything.

**Mitigations.** Small, deliberately boring dependency set: no ORM plugins, no
agent frameworks, no vector database, no UI component library. Lockfiles
committed. All cryptography from `cryptography` and `argon2-cffi`; nothing
invented. Database-level audit triggers survive an application-process
compromise. The frontend was moved off a Next.js version with a published CVE
during this build rather than shipping it.

**Residual.** **High, structurally.** An in-process compromise defeats
in-process controls. Pinning, vendoring, SBOM generation and reproducible builds
are all future work.

---

## T13 — Physical theft of a MyBot Core

**Path.** Someone takes the box.

**Impact.** Everything, if the disk is readable.

**Mitigations designed for.** Secure boot, hardware root of trust,
non-exportable device keys in a secure element, encrypted NVMe, tamper
detection, a physical lockdown button, attestation before a device is trusted.

**Today.** All of this is interface, with software stand-ins that report
`simulated: true` and a `HardwareKeyStore` that raises rather than pretending.
Physical theft of a development machine is T7.

---

## Cross-cutting: what is deliberately *not* mitigated

* **A user who approves a harmful action after being shown the full detail.**
  MyBot's job is to make the consequence legible — subject, before, after,
  reason, risk, reversibility, and a warning when the suggestion came from
  outside. It is not to override the person.
* **Legal compulsion.** Local-first means data lives with the user, which is
  where such a request belongs.
* **A determined attacker with sustained physical access to an unlocked
  machine.** Out of scope for software.

---

## Review triggers

Revisit this document when: a new action type above MEDIUM is registered; any
new external data source is added; a plugin runtime is designed; cloud sync is
introduced; the hardware Core is specified; or any change is proposed to
`MAX_AUTOMATIC_RISK`, `REQUIRES_STANDING_GRANT` or `UNTRUSTED_FORBIDDEN`.
