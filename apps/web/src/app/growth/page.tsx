'use client';

/**
 * GROWTH — what MyBot has learned about you.
 *
 * This screen exists because of a rule that is easy to state and easy to skip:
 * a system that learns things about you which you cannot see or change is
 * surveillance, not assistance. Everything MyBot has concluded is here, in
 * plain language, with the evidence behind it and a way to overrule it.
 *
 * Three deliberate refusals in the design:
 *
 * **No gamification.** No level, no streak, no "your MyBot is 73% grown". This
 * is a transparency surface wearing a friendly hat, and scoring it would
 * encourage people to feed it rather than correct it.
 *
 * **Evidence is always visible.** Every row shows how often something was
 * observed and how often it was contradicted. "You approve these" and "you
 * approved these 12 of 13 times" are different claims, and only one of them is
 * honest about the exception.
 *
 * **Suggestions are offers, never switches.** When MyBot notices you approve
 * something almost every time, it says so and points at the Security Center.
 * There is no control on this page that grants MyBot anything, because
 * learning is not authority.
 */

import Link from 'next/link';
import { useState } from 'react';
import type { FormEvent } from 'react';

import { ApiError, api } from '@/lib/api';
import type { GrowthReport, GrowthRow, LearningSuggestion } from '@/lib/api';
import { Badge, Empty, Notice, formatDate, useAsync } from '@/components/ui';

export default function GrowthPage() {
  const growth = useAsync<GrowthReport>(() => api.get<GrowthReport>('/api/v1/learning'), []);
  const suggestions = useAsync<{ suggestions: LearningSuggestion[] }>(
    () => api.get<{ suggestions: LearningSuggestion[] }>('/api/v1/learning/suggestions'),
    [],
  );

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [correcting, setCorrecting] = useState(false);
  const [draft, setDraft] = useState({ subject: '', correction: '' });

  async function act(id: string, what: 'mute' | 'unmute' | 'confirm' | 'forget') {
    setBusy(id);
    setError(null);
    try {
      if (what === 'forget') {
        await api.delete(`/api/v1/learning/preferences/${id}`);
      } else if (what === 'confirm') {
        await api.post(`/api/v1/learning/preferences/${id}/confirm`);
      } else {
        await api.post(`/api/v1/learning/preferences/${id}/mute?muted=${what === 'mute'}`);
      }
      growth.reload();
      suggestions.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(null);
    }
  }

  async function submitCorrection(event: FormEvent) {
    event.preventDefault();
    if (!draft.subject.trim() || !draft.correction.trim()) return;
    setBusy('new');
    setError(null);
    try {
      await api.post('/api/v1/learning/corrections', draft);
      setDraft({ subject: '', correction: '' });
      setCorrecting(false);
      growth.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(null);
    }
  }

  const report = growth.data;
  const offers = suggestions.data?.suggestions ?? [];

  return (
    <>
      <header className="page-header">
        <h1>What MyBot has learned</h1>
        <p className="page-subtitle">
          {report && report.learned_count > 0
            ? `${report.applied_count} of ${report.learned_count} things are shaping how MyBot behaves. All of it is yours to correct.`
            : 'MyBot learns by watching what you actually do — not by asking a model what it thinks of you.'}
        </p>
      </header>

      {error ? <Notice tone="critical">{error}</Notice> : null}

      <div className="row-between mb-2">
        <div className="section-label" style={{ margin: 0 }}>
          Your record
        </div>
        <button className="btn btn-sm" onClick={() => setCorrecting((v) => !v)}>
          {correcting ? 'Cancel' : 'Correct something'}
        </button>
      </div>

      {correcting ? (
        <form className="card mb-3" onSubmit={submitCorrection}>
          <div className="card-title">Tell MyBot it has something wrong</div>
          <p className="secondary mt-1">
            Corrections apply immediately and never fade. Making you repeat yourself three times
            before it sticks would be infuriating.
          </p>
          <div className="field mt-2">
            <label htmlFor="subject">What is it about?</label>
            <input
              id="subject"
              className="input"
              value={draft.subject}
              onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
              placeholder="my dentist"
              maxLength={200}
            />
          </div>
          <div className="field mt-2">
            <label htmlFor="correction">What is the truth?</label>
            <input
              id="correction"
              className="input"
              value={draft.correction}
              onChange={(e) => setDraft({ ...draft, correction: e.target.value })}
              placeholder="Dr Patel, not Dr Sandhu"
              maxLength={2000}
            />
          </div>
          <div className="btn-row mt-2">
            <button className="btn btn-primary" disabled={busy === 'new'}>
              Save correction
            </button>
          </div>
        </form>
      ) : null}

      {report ? (
        <div className="stat-grid mb-3">
          <Stat label="Learned" value={report.learned_count} />
          <Stat label="Shaping behaviour" value={report.applied_count} />
          <Stat label="Noticed, not acted on" value={report.quarantined_count} />
          <Stat label="Switched off by you" value={report.muted_count} />
        </div>
      ) : null}

      {offers.length > 0 ? (
        <>
          <div className="section-label">MyBot would like to ask</div>
          {offers.map((offer) => (
            <Offer key={offer.action_type} offer={offer} />
          ))}
        </>
      ) : null}

      {report && report.quarantined_count > 0 ? (
        <div className="mb-3">
          <Notice tone="warning">
            <strong>
              {report.quarantined_count} noticed, {report.quarantined_count === 1 ? 'it is' : 'they are'}{' '}
              not being acted on.
            </strong>{' '}
            This came from content you did not write — an email, a document — so MyBot is showing
            it to you rather than believing it. Only you can vouch for it.
          </Notice>
        </div>
      ) : null}

      {growth.loading ? <p className="secondary">Loading…</p> : null}

      {report && report.learned_count === 0 && !growth.loading ? (
        <Empty
          title="Nothing learned yet"
          body="Approve or turn down a few proposals, or correct something MyBot got wrong. It builds from there."
        />
      ) : null}

      {report
        ? Object.entries(report.by_kind).map(([kind, rows]) => (
            <section key={kind}>
              <div className="section-label">{rows[0]?.label ?? kind}</div>
              <div className="card">
                {rows.map((row) => (
                  <LearnedRow
                    key={row.id}
                    row={row}
                    busy={busy === row.id}
                    onAct={(what) => act(row.id, what)}
                  />
                ))}
              </div>
            </section>
          ))
        : null}

      {report && report.learned_count > 0 ? (
        <p className="secondary mt-3">
          {report.note}
          {report.learning_since
            ? ` Learning since ${formatDate(report.learning_since)} — ${report.days_learning} ${
                report.days_learning === 1 ? 'day' : 'days'
              }.`
            : ''}
        </p>
      ) : null}
    </>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

/**
 * An offer, not a switch.
 *
 * The button goes to the Security Center, where the owner creates the
 * permission themselves. MyBot noticing that you approve something is an
 * observation; deciding to stop asking would be a permission grant, and
 * nothing on this page can make one.
 */
function Offer({ offer }: { offer: LearningSuggestion }) {
  return (
    <div className="card mb-2">
      <div className="card-head">
        <span className="list-title">{offer.headline}</span>
        <div className="spacer" />
        <Badge tone="info">{Math.round(offer.confidence * 100)}% consistent</Badge>
      </div>
      <p className="card-body mt-1">{offer.offer}</p>
      <p className="secondary mt-1">
        MyBot cannot set this up on its own. A standing permission is something only you can
        grant.
      </p>
      <div className="btn-row mt-2">
        <Link className="btn btn-sm btn-primary" href="/security">
          Set up a rule
        </Link>
      </div>
    </div>
  );
}

function LearnedRow({
  row,
  busy,
  onAct,
}: {
  row: GrowthRow;
  busy: boolean;
  onAct: (what: 'mute' | 'unmute' | 'confirm' | 'forget') => void;
}) {
  const total = row.evidence_count + row.contradiction_count;
  const evidence =
    row.contradiction_count > 0
      ? `${row.evidence_count} of ${total} times`
      : `${row.evidence_count} ${row.evidence_count === 1 ? 'time' : 'times'}`;

  return (
    <div className="list-row" style={row.muted ? { opacity: 0.55 } : undefined}>
      <div className="list-main">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <span className="list-title">{row.explanation}</span>
          {row.quarantined ? <Badge tone="high">Not acted on</Badge> : null}
          {row.confirmed_by_owner ? <Badge tone="success">You confirmed this</Badge> : null}
          {row.muted ? <Badge tone="neutral">Off</Badge> : null}
          {row.applied && !row.confirmed_by_owner ? <Badge tone="accent">In use</Badge> : null}
        </div>
        <div className="list-sub">
          {row.confirmed_by_owner
            ? 'You told MyBot this directly.'
            : `Observed ${evidence}. Last seen ${formatDate(row.last_observed)}.`}
          {row.quarantined
            ? ' Learned from content you did not write, so MyBot will not act on it unless you confirm it.'
            : ''}
        </div>
      </div>
      <div className="row" style={{ gap: 6 }}>
        {!row.confirmed_by_owner ? (
          <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => onAct('confirm')}>
            {row.quarantined ? "That's true" : "That's right"}
          </button>
        ) : null}
        {!row.quarantined ? (
          <button
            className="btn btn-sm btn-ghost"
            disabled={busy}
            onClick={() => onAct(row.muted ? 'unmute' : 'mute')}
          >
            {row.muted ? 'Use again' : 'Stop using'}
          </button>
        ) : null}
        <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => onAct('forget')}>
          Forget
        </button>
      </div>
    </div>
  );
}
