'use client';

/**
 * AUTOMATIONS — standing rules, and the actions waiting on you.
 *
 * In V0.1 an automation can only surface things; anything above LOW risk
 * still produces a proposal a human approves. This screen says that plainly
 * rather than implying more autonomy than exists.
 */

import { useState } from 'react';

import { ApiError, api } from '@/lib/api';
import type { ActionProposal, Automation } from '@/lib/api';
import { useSession } from '@/components/shell';
import {
  ApprovalSheet,
  Badge,
  Empty,
  Modal,
  Notice,
  RiskBadge,
  formatDateTime,
  useAsync,
} from '@/components/ui';

interface ActionsResponse {
  items: ActionProposal[];
  pending: number;
}

const TRIGGER_LABELS: Record<string, string> = {
  'obligation.due_within': 'An obligation is due soon',
  'subscription.renewing': 'A subscription is about to renew',
  'email.unanswered_for': 'An email has gone unanswered',
  'inbox.urgency_at_least': 'Something urgent appears',
  'document.expiring_within': 'A document is about to expire',
};

const TRIGGER_CONFIG_KEY: Record<string, string> = {
  'obligation.due_within': 'days_before',
  'subscription.renewing': 'days_before',
  'email.unanswered_for': 'hours',
  'document.expiring_within': 'days_before',
};

export default function AutomationsPage() {
  const { me } = useSession();
  const automations = useAsync<{ items: Automation[]; available_triggers: string[]; note: string }>(
    () => api.get<{ items: Automation[]; available_triggers: string[]; note: string }>(
      '/api/v1/automations',
    ),
    [],
  );
  const actions = useAsync<ActionsResponse>(
    () => api.get<ActionsResponse>('/api/v1/actions?limit=60'),
    [],
  );
  const [active, setActive] = useState<ActionProposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState({
    name: '',
    trigger_type: 'obligation.due_within',
    days: 7,
  });

  async function decide(decision: 'approve' | 'reject') {
    if (!active) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/api/v1/actions/${active.id}/${decision}`, {});
      setActive(null);
      actions.reload();
    } catch (err) {
      setError(
        err instanceof ApiError ? [err.message, ...err.reasons].join(' — ') : 'Failed.',
      );
    } finally {
      setBusy(false);
    }
  }

  const pending = (actions.data?.items ?? []).filter(
    (item) => item.status === 'pending_approval',
  );
  const history = (actions.data?.items ?? []).filter(
    (item) => item.status !== 'pending_approval',
  );

  return (
    <>
      <header className="page-header">
        <h1>Automations</h1>
        <p className="page-subtitle">
          Standing rules, and anything waiting for your decision.
        </p>
      </header>

      <Notice tone="info">
        {automations.data?.note ??
          'Automations run through the same policy engine as everything else.'}
      </Notice>

      <div className="section-label">Waiting for you</div>
      {pending.length === 0 ? (
        <Empty title="Nothing is waiting." />
      ) : (
        pending.map((action) => (
          <button
            key={action.id}
            className="card card-interactive"
            style={{ width: '100%', textAlign: 'left', display: 'block' }}
            onClick={() => setActive(action)}
          >
            <div className="card-head">
              <RiskBadge risk={action.risk} />
              {action.derived_from_untrusted ? (
                <Badge tone="high">from external content</Badge>
              ) : null}
              <div className="spacer" />
              <span className="small muted">{formatDateTime(action.created_at)}</span>
            </div>
            <div className="card-title">{action.display}</div>
            {action.reason ? <p className="card-body mt-1">{action.reason}</p> : null}
            <div className="card-foot">
              <span>Requested by {action.requested_by.label}</span>
              <span>Needs {action.required_auth_level}</span>
            </div>
          </button>
        ))
      )}

      <div className="row-between" style={{ marginTop: 30, marginBottom: 12 }}>
        <div className="section-label" style={{ margin: 0 }}>
          Standing rules
        </div>
        <button className="btn btn-sm" onClick={() => setCreating(true)}>
          New automation
        </button>
      </div>
      <div className="card">
        {(automations.data?.items ?? []).length === 0 ? (
          <p className="secondary">
            No automations yet. A good first one: tell me three days before a
            subscription renews.
          </p>
        ) : (
          (automations.data?.items ?? []).map((automation) => (
            <div key={automation.id} className="list-row">
              <div className="list-main">
                <div className="row" style={{ gap: 8 }}>
                  <span className="list-title">{automation.name}</span>
                  {automation.notify_only ? (
                    <Badge tone="neutral">tells you</Badge>
                  ) : (
                    <Badge tone="accent">{automation.action_display}</Badge>
                  )}
                  {automation.action_risk ? (
                    <Badge tone="neutral">{automation.action_risk} risk</Badge>
                  ) : null}
                </div>
                <div className="list-sub">
                  {automation.description ??
                    TRIGGER_LABELS[automation.trigger_type] ??
                    automation.trigger_type.replace(/[._]/g, ' ')}
                  {automation.run_count
                    ? ` · ran ${automation.run_count} time${automation.run_count === 1 ? '' : 's'}`
                    : ' · not run yet'}
                </div>
              </div>
              <div className="row">
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={async () => {
                    await api.patch(
                      `/api/v1/automations/${automation.id}?enabled=${!automation.enabled}`,
                    );
                    automations.reload();
                  }}
                >
                  {automation.enabled ? 'Turn off' : 'Turn on'}
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={async () => {
                    await api.delete(`/api/v1/automations/${automation.id}`);
                    automations.reload();
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="row mt-2">
        <button
          className="btn btn-sm"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await api.post('/api/v1/automations/run', {});
              automations.reload();
              actions.reload();
            } finally {
              setBusy(false);
            }
          }}
        >
          Run them now
        </button>
        <span className="small muted">
          Shows what your automations would do, with no extra authority.
        </span>
      </div>

      <Modal open={creating} onClose={() => setCreating(false)}>
        <div className="modal-head">
          <h2>New automation</h2>
        </div>
        <div className="modal-body">
          <p className="secondary mb-2">
            Automations notice things. Anything they want to <em>do</em> still
            comes to you for approval.
          </p>
          <div className="field">
            <label htmlFor="auto-name">Name</label>
            <input
              id="auto-name"
              className="input"
              placeholder="Tell me before a subscription renews"
              value={draft.name}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
            />
          </div>
          <div className="field">
            <label htmlFor="auto-trigger">When</label>
            <select
              id="auto-trigger"
              className="select"
              value={draft.trigger_type}
              onChange={(event) =>
                setDraft({ ...draft, trigger_type: event.target.value })
              }
            >
              {(automations.data?.available_triggers ?? []).map((trigger) => (
                <option key={trigger} value={trigger}>
                  {TRIGGER_LABELS[trigger] ?? trigger}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="auto-days">How far ahead (days)</label>
            <input
              id="auto-days"
              className="input"
              type="number"
              min={1}
              max={90}
              value={draft.days}
              onChange={(event) =>
                setDraft({ ...draft, days: Number(event.target.value) })
              }
            />
          </div>
        </div>
        <div className="modal-foot">
          <button
            className="btn btn-primary"
            disabled={!draft.name.trim() || busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await api.post('/api/v1/automations', {
                  name: draft.name.trim(),
                  trigger_type: draft.trigger_type,
                  trigger_config: TRIGGER_CONFIG_KEY[draft.trigger_type]
                    ? { [TRIGGER_CONFIG_KEY[draft.trigger_type]]: draft.days }
                    : {},
                });
                setCreating(false);
                setDraft({ ...draft, name: '' });
                automations.reload();
              } catch (err) {
                setError(err instanceof ApiError ? err.message : 'Could not create it.');
              } finally {
                setBusy(false);
              }
            }}
          >
            Create
          </button>
          <button className="btn btn-ghost" onClick={() => setCreating(false)}>
            Cancel
          </button>
        </div>
      </Modal>

      {history.length ? (
        <>
          <div className="section-label">Recent</div>
          <div className="card">
            {history.slice(0, 15).map((action) => (
              <div key={action.id} className="list-row">
                <div className="list-main">
                  <div className="list-title">{action.display}</div>
                  <div className="list-sub">
                    {formatDateTime(action.created_at)}
                    {action.execution.result?.message
                      ? ` · ${action.execution.result.message}`
                      : ''}
                  </div>
                </div>
                <Badge
                  tone={
                    action.status === 'confirmed'
                      ? 'success'
                      : ['blocked', 'failed', 'rejected'].includes(action.status)
                        ? 'critical'
                        : action.status === 'unknown'
                          ? 'high'
                          : 'neutral'
                  }
                >
                  {action.status.replace(/_/g, ' ')}
                </Badge>
              </div>
            ))}
          </div>
        </>
      ) : null}

      <Modal open={Boolean(active)} onClose={() => setActive(null)}>
        {active ? (
          <ApprovalSheet
            action={active}
            busy={busy}
            error={error}
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
