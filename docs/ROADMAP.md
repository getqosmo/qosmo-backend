# Roadmap

## V0.1 — Alpha (this release)

Life Graph · memory · Life Inbox · morning brief · document ingestion ·
simulated calendar and email · action proposals with approval · policy engine ·
Action Firewall · hash-chained audit · Vault · lockdown · Security Center ·
grounded chat · 210 tests.

## V0.2 — Automations and real connectors

* Google OAuth flow wired end to end; Calendar and Gmail verified against live
  endpoints (the adapters exist; the consent flow does not).
* Automations that act on LOW-risk actions within explicit standing grants.
* Subscription intelligence: detect renewals from transactions rather than only
  from stored entities.
* Travel awareness: flights, check-ins, travel time between calendar events.
* Local model support via Ollama, making `PERSONAL`+ context viable without
  leaving the machine.
* OCR for scanned documents.
* Chat history retention enforcement.
* Rate limiting and account lockout.
* httpOnly cookie sessions.

## V0.3 — Reach

* Phone agent: call a service provider on the owner's behalf, with recording
  consent and a full transcript in the audit trail.
* Browser agent: sandboxed, scoped to a single task, proposals only.
* Service marketplace and the plugin runtime — permissions declared in a
  manifest, evaluated by the same policy engine, sandboxed, never given raw
  credentials.
* Household management: shared obligations, multiple people, per-person scopes.

## V1 — Authority

The version where MyBot is trusted to act, which is why everything before it
exists.

* Financial actions: bill payment, transfers, with per-recipient limits,
  velocity checks, cooling-off periods and physical-presence approval.
* Government interactions: renewals and filings.
* Family mode: delegation with bounded scopes and visible audit for each
  member.
* **MyBot Core hardware**: secure boot, hardware root of trust, non-exportable
  device keys, encrypted NVMe, tamper detection, a physical lockdown button,
  on-device inference, attestation, secure recovery.
* MyBot Key: a hardware second factor.
* Developer platform.

## Security work that gates the above

Roughly in order:

1. **Encrypted backup with a real recovery story.** Losing the master key today
   loses the Vault. Sharded escrow with user-held shares — designed carefully,
   not improvised.
2. **Per-record encryption for personal content.** A stolen database file
   currently discloses the Life Graph.
3. **Supply chain**: pinning, vendoring, SBOM, reproducible builds.
4. **Zero-knowledge cloud sync**, before any cloud component holds real data.
5. **Formal review of the policy engine.** It is small enough to reason about
   exhaustively, and it is the component where a bug is worst.
6. **Independent security audit** before anyone's real money is reachable.

## Explicitly not planned

Selling or brokering user data; training on user content; a cloud service that
can read the Vault; any autonomy level that removes the human from
irreversible decisions.
