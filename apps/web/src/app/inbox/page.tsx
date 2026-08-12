'use client';

/**
 * INBOX — every card MyBot has surfaced, in deterministic priority order.
 *
 * Distinct from TODAY: this includes the FYI items and the things that have
 * been handled, so the user can see the full picture rather than only the
 * urgent slice.
 */

import { useState } from 'react';

import { api } from '@/lib/api';
import type { InboxItem } from '@/lib/api';
import {
  Badge,
  Empty,
  Notice,
  UrgencyBadge,
  formatDate,
  relativeDays,
  useAsync,
} from '@/components/ui';

interface InboxResponse {
  items: InboxItem[];
  counts: Record<string, number>;
}

const FILTERS = ['all', 'urgent', 'money', 'work', 'decision', 'travel', 'home', 'fyi'];

export default function InboxPage() {
  const [filter, setFilter] = useState('all');
  const { data, error, loading, reload } = useAsync<InboxResponse>(
    () => api.get<InboxResponse>('/api/v1/inbox?refresh=true&limit=200'),
    [],
  );

  if (loading) return <div className="skeleton" style={{ height: 300 }} />;
  if (error || !data) return <Notice tone="critical">{error ?? 'Could not load.'}</Notice>;

  const items =
    filter === 'all' ? data.items : data.items.filter((item) => item.category === filter);

  return (
    <>
      <header className="page-header">
        <h1>Life Inbox</h1>
        <p className="page-subtitle">
          Everything MyBot is tracking, ordered by what matters most.
        </p>
      </header>

      <div className="row wrap mb-2">
        {FILTERS.map((option) => (
          <button
            key={option}
            className={`suggestion${filter === option ? ' badge-accent' : ''}`}
            onClick={() => setFilter(option)}
            style={
              filter === option
                ? { borderColor: 'var(--accent)', color: 'var(--accent)' }
                : undefined
            }
          >
            {option}
            {data.counts[option] ? ` · ${data.counts[option]}` : ''}
          </button>
        ))}
      </div>

      {items.length === 0 ? (
        <Empty title="Nothing here." body="MyBot will surface things as they come up." />
      ) : (
        items.map((item) => (
          <article key={item.id} className="inbox-card" data-urgency={item.urgency}>
            <div className="card-head">
              <UrgencyBadge urgency={item.urgency} />
              <Badge tone="neutral">{item.category}</Badge>
              <div className="spacer" />
              <span className="small muted mono">{Math.round(item.priority_score)}</span>
            </div>
            <div className="card-title">{item.title}</div>
            <p className="card-body mt-1">{item.explanation}</p>

            {item.reason ? (
              <details className="mt-2">
                <summary
                  className="small"
                  style={{ cursor: 'pointer', color: 'var(--text-tertiary)' }}
                >
                  Why?
                </summary>
                <p className="small secondary mt-1">{item.reason}</p>
                <p className="small mono muted mt-1">
                  Rule: {item.rule_id}
                  {item.source_ids.length ? ` · ${item.source_ids.join(', ')}` : ''}
                </p>
              </details>
            ) : null}

            <div className="card-foot">
              {item.due_at ? (
                <span>
                  {formatDate(item.due_at)} · {relativeDays(item.due_at)}
                </span>
              ) : null}
              <span>{Math.round(item.confidence * 100)}% confident</span>
              <div className="spacer" />
              <div className="btn-row">
                <button
                  className="btn btn-sm"
                  onClick={async () => {
                    await api.post(`/api/v1/inbox/${item.id}/resolve`, {});
                    reload();
                  }}
                >
                  Done
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={async () => {
                    await api.post(`/api/v1/inbox/${item.id}/snooze`, { hours: 24 });
                    reload();
                  }}
                >
                  Snooze
                </button>
              </div>
            </div>
          </article>
        ))
      )}
    </>
  );
}
