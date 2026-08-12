'use client';

/**
 * WHAT LEFT YOUR MACHINE.
 *
 * The one privacy question that actually settles anything, answered
 * completely: show me everything that left, when, where it went, and why.
 *
 * The screen is deliberately unglamorous. It is a ledger, and a ledger earns
 * trust by being boring and complete rather than by being reassuring. Three
 * things it refuses to do:
 *
 * **It never rounds down to zero.** Rows that predate the ledger are shown as
 * unknown, in their own count, and the "nothing left" headline is withheld
 * while any exist. "We have no record" and "nothing happened" are different
 * sentences.
 *
 * **It shows failures.** A request that timed out still left.
 *
 * **It shows the fingerprint, not the prompt.** The hash is the proof that the
 * words themselves were never kept — a privacy screen that logged what it
 * reports on would have made things worse.
 */

import { api } from '@/lib/api';
import type { EgressEvent, EgressLedger } from '@/lib/api';
import { Badge, Empty, Notice, formatDateTime, useAsync } from '@/components/ui';

export default function EgressPage() {
  const ledger = useAsync<EgressLedger>(
    () => api.get<EgressLedger>('/api/v1/egress?only_external=false&limit=100'),
    [],
  );
  const data = ledger.data;

  return (
    <>
      <header className="page-header">
        <h1>What left your machine</h1>
        <p className="page-subtitle">
          Every request MyBot made on your behalf in the last {data?.window_days ?? 30} days —
          models it asked, accounts it checked, and the ones that failed.
        </p>
      </header>

      {data ? <Headline data={data} /> : null}

      {data ? (
        <div className="stat-grid mb-3">
          <div className="stat">
            <div className="stat-value">{data.left_machine}</div>
            <div className="stat-label">Left this machine</div>
          </div>
          <div className="stat">
            <div className="stat-value">{data.stayed_local}</div>
            <div className="stat-label">Answered here</div>
          </div>
          <div className="stat">
            <div className="stat-value">{data.unknown}</div>
            <div className="stat-label">Unaccounted for</div>
          </div>
        </div>
      ) : null}

      {data && data.destinations.length > 0 ? (
        <>
          <div className="section-label">Where it went</div>
          <div className="card mb-3">
            {data.destinations.map((d) => (
              <div className="list-row" key={d.host}>
                <div className="list-main">
                  <span className="list-title mono">{d.host}</span>
                </div>
                <span className="small muted">
                  {d.count} {d.count === 1 ? 'request' : 'requests'}
                </span>
              </div>
            ))}
          </div>
        </>
      ) : null}

      <div className="section-label">Every request</div>

      {ledger.loading ? <p className="secondary">Loading…</p> : null}

      {data && data.events.length === 0 && !ledger.loading ? (
        <Empty
          title="Nothing yet"
          body="MyBot has not made a single outbound request. When it does — a model, or a check of a connected account — it will be listed here."
        />
      ) : null}

      {data && data.events.length > 0 ? (
        <div className="card">
          {data.events.map((event) => (
            <EgressRow key={event.id} event={event} />
          ))}
        </div>
      ) : null}

      {data ? <p className="secondary mt-3">{data.note}</p> : null}
    </>
  );
}

function Headline({ data }: { data: EgressLedger }) {
  if (data.unknown > 0) {
    return (
      <div className="mb-3">
        <Notice tone="warning">
          <strong>{data.unknown} requests cannot be accounted for.</strong> They were made
          before this ledger existed, so MyBot genuinely does not know whether they left. It
          would rather say that than round it down to zero.
        </Notice>
      </div>
    );
  }
  if (data.nothing_left && data.total_events > 0) {
    return (
      <div className="mb-3">
        <Notice tone="info">
          <strong>Nothing has left this machine.</strong> All {data.stayed_local} requests were
          answered here. This count comes from the same record as everything else on this page
          — it is checkable, not a setting.
        </Notice>
      </div>
    );
  }
  return null;
}

function EgressRow({ event }: { event: EgressEvent }) {
  const unknown = event.left_machine === null;
  return (
    <div className="list-row">
      <div className="list-main">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <span className="list-title">{event.what}</span>
          {unknown ? (
            <Badge tone="medium">Unknown</Badge>
          ) : event.left_machine ? (
            <Badge tone="high">Left your machine</Badge>
          ) : (
            <Badge tone="success">Stayed here</Badge>
          )}
          {event.identifiers_masked ? <Badge tone="neutral">Names masked</Badge> : null}
          {event.status !== 'ok' ? <Badge tone="critical">{event.outcome}</Badge> : null}
        </div>
        <div className="list-sub">
          {event.destination ? `Sent to ${event.destination}. ` : ''}
          Carried {event.sent}.{' '}
          {event.included_outside_content ? 'Included content from outside you. ' : ''}
          {formatDateTime(event.at)}
        </div>
      </div>
      <span
        className="small muted mono"
        title="A fingerprint. The prompt itself was never stored."
      >
        {event.prompt_fingerprint || '—'}
      </span>
    </div>
  );
}
