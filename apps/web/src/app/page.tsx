'use client';

/**
 * TODAY — the home screen.
 *
 * Not a chat box. The first thing a person sees is a sentence about their day
 * and the small number of things that actually need them, followed by what
 * MyBot handled on its own. Everything on this page is rendered from the
 * deterministic brief; nothing here is model-generated prose.
 */

import { useEffect, useState } from 'react';

import { ApiError, api } from '@/lib/api';
import type { ActionProposal, InboxItem, TodayResponse } from '@/lib/api';
import { useSession } from '@/components/shell';
import {
  ApprovalSheet,
  Badge,
  Empty,
  Modal,
  Notice,
  Spinner,
  UrgencyBadge,
  relativeDays,
  useAsync,
} from '@/components/ui';

export default function TodayPage() {
  const { me, setPending } = useSession();
  const { data, error, loading, reload } = useAsync<TodayResponse>(
    () => api.get<TodayResponse>('/api/v1/today'),
    [],
  );
  const [active, setActive] = useState<ActionProposal | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (data) setPending(data.needs_attention_count);
  }, [data, setPending]);

  if (loading) {
    return (
      <div className="stack">
        <div className="skeleton" style={{ height: 34, width: 280 }} />
        <div className="skeleton" style={{ height: 18, width: 200 }} />
        <div className="skeleton" style={{ height: 92, marginTop: 20 }} />
        <div className="skeleton" style={{ height: 92 }} />
      </div>
    );
  }

  if (error || !data) {
    return <Notice tone="critical">{error ?? 'Could not load today.'}</Notice>;
  }

  const { brief, items, coverage } = data;
  const needsAttention = items.filter(
    (item) => item.priority_score >= 35 && !['fyi', 'handled'].includes(item.category),
  );
  const unavailable = Object.entries(coverage).filter(([, value]) => !value.ok);

  async function openAction(item: InboxItem) {
    setActionError(null);
    try {
      if (item.action_proposal_id) {
        setActive(await api.get<ActionProposal>(`/api/v1/actions/${item.action_proposal_id}`));
        return;
      }
      const suggestion = item.possible_actions.find(
        (candidate) => candidate.requires_approval && candidate.available && candidate.params,
      );
      if (!suggestion) return;
      // The parameters come from MyBot, not from this browser. See
      // PossibleAction in lib/api.ts for why that matters.
      const created = await api.post<ActionProposal>('/api/v1/actions', {
        action_type: suggestion.action_type,
        params: suggestion.params,
        reason: item.explanation,
        inbox_item_id: item.id,
      });
      setActive(created);
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? [err.message, ...err.reasons].join(' ')
          : 'Could not prepare that action.',
      );
    }
  }

  async function decide(decision: 'approve' | 'reject') {
    if (!active) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.post(`/api/v1/actions/${active.id}/${decision}`, {});
      setActive(null);
      reload();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? [err.message, ...err.reasons].join(' — ')
          : 'Something went wrong.',
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>{brief.greeting}</h1>
        <p className="page-subtitle">
          {new Date().toLocaleDateString(undefined, {
            weekday: 'long',
            month: 'long',
            day: 'numeric',
          })}
          {' · '}
          {brief.summary}
        </p>
      </header>

      {actionError ? <Notice tone="critical">{actionError}</Notice> : null}

      {unavailable.length ? (
        <Notice tone="warning">
          MyBot could not check {unavailable.map(([key]) => key).join(', ')}, so
          this may be incomplete.
        </Notice>
      ) : null}

      {needsAttention.length === 0 ? (
        <Empty
          title="Nothing needs you right now."
          body={brief.closing}
        />
      ) : (
        <>
          <div className="section-label">Things that need you</div>
          {needsAttention.map((item) => (
            <article
              key={item.id}
              className="inbox-card"
              data-urgency={item.urgency}
            >
              <div className="card-head">
                <UrgencyBadge urgency={item.urgency} />
                <Badge tone="neutral">{item.category}</Badge>
                {item.confidence < 0.85 ? (
                  <Badge tone="neutral">
                    {Math.round(item.confidence * 100)}% confident
                  </Badge>
                ) : null}
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
                  {item.source_ids.length ? (
                    <p className="small mono muted mt-1">
                      Sources: {item.source_ids.join(', ')}
                    </p>
                  ) : null}
                </details>
              ) : null}

              {item.possible_actions
                .filter((candidate) => candidate.available === false)
                .slice(0, 1)
                .map((candidate) => (
                  <p key={candidate.action_type} className="small muted mt-2">
                    {candidate.unavailable_reason}
                  </p>
                ))}

              <div className="card-foot">
                {item.due_at ? <span>Due {relativeDays(item.due_at)}</span> : null}
                <div className="spacer" />
                <div className="btn-row">
                  {item.possible_actions
                    .filter((candidate) => candidate.requires_approval)
                    .slice(0, 1)
                    .map((candidate) =>
                      candidate.available ? (
                        <button
                          key={candidate.action_type}
                          className="btn btn-sm btn-primary"
                          onClick={() => openAction(item)}
                        >
                          {candidate.label}
                        </button>
                      ) : (
                        <button
                          key={candidate.action_type}
                          className="btn btn-sm"
                          disabled
                          title={candidate.unavailable_reason}
                        >
                          {candidate.label}
                        </button>
                      ),
                    )}
                  {item.possible_actions.some(
                    (candidate) => candidate.action_type === 'obligation.complete',
                  ) && item.obligation_id ? (
                    <button
                      className="btn btn-sm"
                      onClick={async () => {
                        await api.post(
                          `/api/v1/obligations/${item.obligation_id}/complete`,
                          {},
                        );
                        await api.post(`/api/v1/inbox/${item.id}/resolve`, {});
                        reload();
                      }}
                    >
                      Mark as done
                    </button>
                  ) : null}
                  <button
                    className="btn btn-sm btn-ghost"
                    onClick={async () => {
                      await api.post(`/api/v1/inbox/${item.id}/dismiss`, {});
                      reload();
                    }}
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </article>
          ))}
        </>
      )}

      {brief.handled.length ? (
        <>
          <div className="section-label">MyBot handled</div>
          <div className="card">
            {brief.handled.map((line, index) => (
              <div key={index} className="handled-item">
                <span className="check">✓</span>
                <span>{line.text}</span>
              </div>
            ))}
          </div>
        </>
      ) : null}

      {brief.schedule.length ? (
        <>
          <div className="section-label">Today&rsquo;s schedule</div>
          <div className="card">
            {brief.schedule.map((line, index) => {
              const [time, ...rest] = line.text.split(' — ');
              return (
                <div key={index} className="schedule-row">
                  <span className="schedule-time">{time}</span>
                  <span>{rest.join(' — ')}</span>
                </div>
              );
            })}
          </div>
        </>
      ) : null}

      <p className="small muted mt-3">{brief.closing}</p>

      <Modal open={Boolean(active)} onClose={() => setActive(null)}>
        {active ? (
          <ApprovalSheet
            action={active}
            busy={busy}
            error={actionError}
            authLevel={me?.auth_level ?? 'BASIC'}
            onApprove={() => decide('approve')}
            onReject={() => decide('reject')}
            onClose={() => setActive(null)}
          />
        ) : null}
      </Modal>
    </>
  );
}
