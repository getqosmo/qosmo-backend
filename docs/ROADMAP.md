# Roadmap

## V0.1 — Alpha (this release)

Life Graph · memory · Life Inbox · morning brief · document ingestion ·
simulated calendar and email · action proposals with approval · policy engine ·
Action Firewall · hash-chained audit · Vault · lockdown · Security Center ·
grounded chat.

**Delivered since the first cut**: the proactive daemon (MyBot notices things
while you are *not* looking, which is what "proactive" has to mean), the
automations engine, notifications with restraint built in, rate limiting and
brute-force protection, and the brand system.

## V0.2 — Real connectors

* Google OAuth flow wired end to end; Calendar and Gmail verified against live
  endpoints (the adapters exist; the consent flow does not).
* Subscription intelligence: detect renewals from transactions rather than only
  from stored entities.
* Travel awareness: flights, check-ins, travel time between calendar events.
* Local model support via Ollama, making `PERSONAL`+ context viable without
  leaving the machine.
* OCR for scanned documents.
* Push and email notification channels — the model and the restraint logic are
  in place; only the delivery transports are missing.
* Server-sent events so the UI stops polling for notifications.
* Chat history retention enforcement.
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

1. ~~**Encrypted backup with a real recovery story.**~~ **Built.** A fresh
   random key per backup, wrapped once per recovery path (24-word phrase via
   Argon2id, plus optional recovery contacts), with no escrow held by us.
   `mybot backup` / `mybot restore`; see SECURITY.md §10. What remains is
   Shamir-style *m*-of-*n* share splitting for the "3 of 5 friends" case — the
   wrap format reserves a field for it, and it is deliberately unimplemented
   rather than hand-rolled. Scheduling and rotation are also still manual.
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
