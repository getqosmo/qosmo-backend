# Positioning

## The mistake to avoid first

MyBot is not a better Alexa. Competing on assistant features — voice, timers,
music, smart home — is competing on the axis where Amazon and Google have a
decade's head start, thousands of engineers, and hardware in the room already.
That fight is unwinnable and, more importantly, uninteresting: nobody's life is
worse because their timer app is mediocre.

The winnable position is a category those companies **structurally cannot
enter**, for reasons that are not about engineering effort.

## The structural argument

Google's revenue is advertising. Amazon's is commerce. In both cases the
outbound flow of personal data *is* the product — not a side effect of it, not
a regrettable necessity, the actual mechanism by which the company is paid.

That has three consequences a competitor can rely on permanently:

**They cannot run local-first.** A model of you that never leaves your house
cannot be targeted against, and cannot inform a recommendation surface. This is
not a feature they have deprioritised; it is incompatible with the P&L.

**They cannot show you the ledger.** MyBot's "What has left" screen is a
complete, itemised record of every outbound request. For Google, that screen
would be a list of their own business model, on a page the customer reads.
The incentive runs the other way and always will.

**They cannot let you own the model of you.** Google Takeout gives you your
data — the emails, the photos. It does not give you the *inference*: what they
have concluded about you, in plain language, with the evidence, correctable and
deletable and portable. That inference is the asset. Handing it over is handing
over the business.

MyBot's whole architecture is the inverse bet: the inference belongs to the
user, is readable by the user, and is worthless to anybody else.

## The four things we can offer that they cannot

Each of these exists in the codebase today. That constraint is the point — a
positioning document listing things we intend to build is a wish list.

### 1. A complete egress ledger

*"Show me every single thing that has left my machine, when, where it went,
and why."*

`GET /api/v1/egress`. Every model call *and* every check of a connected
account, including the ones that failed — a request that timed out still left,
and polling a mailbox sends your identity outward even though the mail comes
back. Built from the rows the doing code writes, so it cannot under-report
without the work itself not having happened. With everything local it reads
**zero**, and that zero comes from the same tables as every other number on the
page, so it is checkable rather than claimed.

No major assistant ships this. Not because it is hard.

### 2. Learning you can read, correct, and take with you

`GET /api/v1/learning`. Everything MyBot has concluded about its owner, in
plain language, with the observation count behind each conclusion, and a button
to correct or delete any of it. It travels in every encrypted backup, so it
survives a machine and survives us.

Amazon and Google both build a model of you. Neither will show it to you in a
form you could argue with.

### 3. Learning that cannot become authority

MyBot will notice you approved something twelve times out of thirteen, and it
will *offer* to make that a rule. It will not decide. Every learnable kind
declares which surfaces it may influence, and the authority surfaces —
permissions, risk, approval, execution — are unclaimable by construction.

The competitive point is not that this is clever. It is that an
engagement-optimised assistant has a standing incentive to reduce friction, and
"stop asking" is the friction most worth removing. MyBot's incentive is to be
trusted with more of your life over a decade, which means the asking is the
product.

### 4. Recovery without an escrow

`mybot backup` seals your data under a key wrapped once per recovery path you
hold — a phrase, a trusted contact. **No copy is held by us**, which also means
losing every path loses the data, and we say so on the marketing page.

Every cloud assistant can read your data because it must be able to restore it.
That is the same capability, described sympathetically.

## What we should not claim

Being disciplined here is a competitive advantage, not a limitation — the
category is crowded with products that overclaim, and the buyer we want is the
one who has noticed.

- **Not "unhackable."** Written into the security rules, and there is a test.
- **Not "as smart as a frontier model, offline."** Nobody can hand you private
  frontier weights on consumer hardware today. What we offer is that the model
  is *swappable* and the individual is *permanent* — see `mybot model-check`,
  which measures whether a given local model is actually fit for each job and
  stops routing to it when it is not.
- **Not "the future of humanity depends on this."** It is a very good personal
  operating system with an unusually honest architecture. The structural
  argument above is strong precisely because it is checkable; grand civilisational
  claims are not, and pairing them dilutes the part that is.
- **Not "we don't sell your data."** Every company says that. Say the thing they
  cannot: *there is no server holding it.*

## The one-line version

> Alexa and Google can tell you what the weather is.
> MyBot can tell you everything it has ever done on your behalf, everything it
> has learned about you, and everything that has left your house — and then
> hand you the keys.

## Where the honest gaps are

Stated because a positioning document that only lists strengths is marketing,
and because these are what a serious buyer will find in week two.

- Connectors are simulated by default; the Google adapters are code-complete but
  unverified against live endpoints. Their egress *is* now itemised, so a real
  connection will show up in the ledger the moment one is wired.
- No local model has been run against this build — sovereign mode is a correct
  control over a capability that has not yet been demonstrated on real hardware.
- Money cannot move. Deliberately, in V0.1.
- No voice, no hardware, no mobile app. The Core is a roadmap item.
