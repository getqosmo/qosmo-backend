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
import type { ActionProposal, SecurityOverview } from '@/lib/api';
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

export default function AutomationsPage() {
  const { me } = useSession();
  const overview = useAsync<SecurityOverview>(
    () => api.get<SecurityOverview>('/api/v1/security'),
    [],
  );
  const actions = useAsync<ActionsResponse>(
    () => api.get<ActionsResponse>('/api/v1/actions?limit=60'),
    [],
  );
  const [active, setActive] = useState<ActionProposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        In this release MyBot prepares, it does not act on its own. Anything
        above low risk waits for you here.
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

      <div className="section-label">Standing rules</div>
      <div className="card">
        {(overview.data?.automations ?? []).length === 0 ? (
          <p className="secondary">No automations yet.</p>
        ) : (
          (overview.data?.automations ?? []).map((automation) => (
            <div key={automation.id} className="list-row">
              <div className="list-main">
                <div className="list-title">{automation.name}</div>
                <div className="list-sub">
                  {automation.description ?? automation.trigger_type}
                </div>
              </div>
              <Badge tone={automation.enabled ? 'success' : 'neutral'}>
                {automation.enabled ? 'on' : 'off'}
              </Badge>
            </div>
          ))
        )}
      </div>

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
