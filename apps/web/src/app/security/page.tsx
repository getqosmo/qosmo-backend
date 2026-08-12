'use client';

/**
 * SECURITY CENTER — a first-class product surface.
 *
 * The design target from the spec: a person should be able to answer "what
 * can MyBot currently do?" in under thirty seconds. So the first thing on the
 * page is a single number — how many things MyBot can do without asking —
 * followed by lockdown, then the details.
 *
 * Nothing here is alarming by default. Security should feel like a well-made
 * lock, not a warning siren.
 */

import { useState } from 'react';

import { ApiError, api } from '@/lib/api';
import type { SecurityOverview } from '@/lib/api';
import { useSession } from '@/components/shell';
import {
  Badge,
  Modal,
  Notice,
  RiskBadge,
  Spinner,
  formatDateTime,
  useAsync,
} from '@/components/ui';

export default function SecurityPage() {
  const { me, refresh } = useSession();
  const { data, error, loading, reload } = useAsync<SecurityOverview>(
    () => api.get<SecurityOverview>('/api/v1/security'),
    [],
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [elevating, setElevating] = useState(false);
  const [code, setCode] = useState('');

  if (loading) return <div className="skeleton" style={{ height: 400 }} />;
  if (error || !data) return <Notice tone="critical">{error ?? 'Could not load.'}</Notice>;

  async function run(fn: () => Promise<{ message?: string }>) {
    setBusy(true);
    setProblem(null);
    try {
      const result = await fn();
      setMessage(result.message ?? 'Done.');
      reload();
      await refresh();
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  const { lockdown, summary } = data;

  return (
    <>
      <header className="page-header">
        <h1>Security</h1>
        <p className="page-subtitle">
          What MyBot can do, who approved it, and everything it has done.
        </p>
      </header>

      {message ? <Notice tone="info">{message}</Notice> : null}
      {problem ? <Notice tone="critical">{problem}</Notice> : null}

      {lockdown.locked ? (
        <Notice tone="critical">
          <strong>MyBot is locked.</strong> External actions are blocked and
          automations are off.
          {lockdown.reason ? ` Reason: ${lockdown.reason}.` : ''} Unlocking
          requires {lockdown.unlock_requires} authentication.
        </Notice>
      ) : null}

      <div className="stat-grid">
        <div className="stat">
          <div className="stat-value">{summary.can_act_without_asking}</div>
          <div className="stat-label">things MyBot can do without asking</div>
        </div>
        <div className="stat">
          <div className="stat-value">{summary.standing_permissions}</div>
          <div className="stat-label">standing permissions</div>
        </div>
        <div className="stat">
          <div className="stat-value">{summary.connected_services}</div>
          <div className="stat-label">connected services</div>
        </div>
        <div className="stat">
          <div className="stat-value">{summary.pending_approvals}</div>
          <div className="stat-label">waiting for you</div>
        </div>
      </div>

      <div className="card mb-2">
        <div className="row-between">
          <div>
            <div className="card-title">
              {lockdown.locked ? 'MyBot is locked' : 'Lockdown'}
            </div>
            <p className="small secondary mt-1">
              {lockdown.locked
                ? 'Nothing can reach outside MyBot until you unlock it.'
                : 'Immediately stop all external actions, void pending approvals and disable automations.'}
            </p>
          </div>
          {lockdown.locked ? (
            <button
              className="btn btn-primary"
              disabled={busy}
              onClick={() =>
                run(() =>
                  api.post<{ message: string }>('/api/v1/security/unlock', {
                    restore_automations: true,
                  }),
                )
              }
            >
              {busy ? <Spinner /> : null} Unlock
            </button>
          ) : (
            <button
              className="btn btn-danger"
              disabled={busy}
              onClick={() =>
                run(() =>
                  api.post<{ message: string }>('/api/v1/security/lockdown', {
                    reason: 'Locked from the Security Center',
                  }),
                )
              }
            >
              Lock MyBot
            </button>
          )}
        </div>
      </div>

      <div className="card mb-2">
        <div className="row-between">
          <div>
            <div className="card-title">Authentication</div>
            <p className="small secondary mt-1">
              You are at <strong>{me?.auth_level}</strong>. Higher-risk actions
              need STRONG, which expires after a few minutes.
            </p>
          </div>
          <button className="btn" onClick={() => setElevating(true)}>
            Verify second factor
          </button>
        </div>
      </div>

      <div className="section-label">What MyBot is allowed to do</div>
      {data.permissions.length === 0 ? (
        <div className="card">
          <p className="secondary">
            No standing permissions. MyBot can prepare things, but every action
            needs your approval.
          </p>
        </div>
      ) : (
        <div className="card">
          {data.permissions.map((rule) => (
            <div key={rule.id} className="list-row">
              <div className="list-main">
                <div className="row" style={{ gap: 8 }}>
                  <span className="list-title">{rule.display}</span>
                  <RiskBadge risk={rule.risk} />
                  {rule.allow_automatic && !rule.requires_confirmation ? (
                    <Badge tone="high">automatic</Badge>
                  ) : (
                    <Badge tone="neutral">asks first</Badge>
                  )}
                </div>
                <div className="list-sub">
                  {rule.description ?? rule.action_type}
                  {rule.max_amount ? ` · up to $${rule.max_amount.toFixed(2)}` : ''}
                  {rule.allowed_recipients.length
                    ? ` · only to ${rule.allowed_recipients.join(', ')}`
                    : ''}
                  {rule.requires_strong_auth ? ' · strong auth' : ''}
                </div>
              </div>
              <button
                className="btn btn-sm btn-ghost"
                onClick={() =>
                  run(async () => {
                    await api.delete(`/api/v1/security/permissions/${rule.id}`);
                    return { message: 'Permission revoked.' };
                  })
                }
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="section-label">Connected services</div>
      <div className="card">
        {data.integrations.length === 0 ? (
          <p className="secondary">Nothing connected.</p>
        ) : (
          data.integrations.map((integration) => (
            <div key={integration.id} className="list-row">
              <div className="list-main">
                <div className="row" style={{ gap: 8 }}>
                  <span className="list-title">{integration.display_name}</span>
                  {integration.simulated ? (
                    <Badge tone="info">simulated</Badge>
                  ) : (
                    <Badge tone="success">connected</Badge>
                  )}
                  {integration.write_enabled ? (
                    <Badge tone="high">can write</Badge>
                  ) : (
                    <Badge tone="neutral">read only</Badge>
                  )}
                </div>
                <div className="list-sub">
                  {integration.scopes.length
                    ? integration.scopes.join(', ')
                    : 'no scopes granted'}
                  {integration.last_sync_at
                    ? ` · synced ${formatDateTime(integration.last_sync_at)}`
                    : ''}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="section-label">Devices</div>
      <div className="card">
        {data.devices.map((device) => (
          <div key={device.id} className="list-row">
            <div className="list-main">
              <div className="row" style={{ gap: 8 }}>
                <span className="list-title">{device.name}</span>
                {device.revoked ? (
                  <Badge tone="neutral">revoked</Badge>
                ) : device.trusted ? (
                  <Badge tone="success">trusted</Badge>
                ) : (
                  <Badge tone="neutral">not trusted</Badge>
                )}
              </div>
              <div className="list-sub">
                {device.kind}
                {device.last_seen_at
                  ? ` · last seen ${formatDateTime(device.last_seen_at)}`
                  : ''}
              </div>
            </div>
            {!device.revoked ? (
              <button
                className="btn btn-sm btn-ghost"
                onClick={() =>
                  run(async () => {
                    await api.delete(`/api/v1/security/devices/${device.id}`);
                    return { message: 'Device revoked.' };
                  })
                }
              >
                Revoke
              </button>
            ) : null}
          </div>
        ))}
      </div>

      <div className="section-label">Recent actions</div>
      <div className="card">
        {data.recent_actions.length === 0 ? (
          <p className="secondary">MyBot has not done anything yet.</p>
        ) : (
          data.recent_actions.map((action) => (
            <div key={action.id} className="list-row">
              <div className="list-main">
                <div className="row" style={{ gap: 8 }}>
                  <span className="list-title">{action.display}</span>
                  <RiskBadge risk={action.risk} />
                  {action.derived_from_untrusted ? (
                    <Badge tone="high">from external content</Badge>
                  ) : null}
                </div>
                <div className="list-sub">
                  {action.requested_by} · {formatDateTime(action.created_at)}
                </div>
              </div>
              <Badge
                tone={
                  action.status === 'confirmed'
                    ? 'success'
                    : action.status === 'blocked' || action.status === 'failed'
                      ? 'critical'
                      : action.status === 'unknown'
                        ? 'high'
                        : 'neutral'
                }
              >
                {action.status.replace(/_/g, ' ')}
              </Badge>
            </div>
          ))
        )}
      </div>

      <div className="section-label">Security events</div>
      <div className="card">
        {data.security_events.length === 0 ? (
          <p className="secondary">Nothing to report.</p>
        ) : (
          data.security_events.slice(0, 12).map((event) => (
            <div key={event.id} className="list-row">
              <div className="list-main">
                <div className="list-title">{event.summary}</div>
                <div className="list-sub">
                  {event.type.replace(/_/g, ' ')} · {formatDateTime(event.created_at)}
                </div>
              </div>
              <Badge
                tone={
                  event.severity === 'critical'
                    ? 'critical'
                    : event.severity === 'warning'
                      ? 'high'
                      : 'neutral'
                }
              >
                {event.severity}
              </Badge>
            </div>
          ))
        )}
      </div>

      <div className="section-label">Audit integrity</div>
      <div className="card">
        <div className="row-between">
          <div>
            <div className="card-title">
              {data.audit.ok ? 'History is intact' : 'History has been altered'}
            </div>
            <p className="small secondary mt-1">
              {data.audit.events_checked} events verified by hash chain.
              {data.audit.problem ? ` ${data.audit.problem}` : ''}
            </p>
          </div>
          <Badge tone={data.audit.ok ? 'success' : 'critical'}>
            {data.audit.ok ? 'verified' : 'tampered'}
          </Badge>
        </div>
      </div>

      <Modal open={elevating} onClose={() => setElevating(false)}>
        <div className="modal-head">
          <h2>Verify your second factor</h2>
        </div>
        <div className="modal-body">
          <p className="secondary mb-2">
            Enter the current 6-digit code. This raises you to STRONG for a few
            minutes, then expires automatically.
          </p>
          <input
            className="input mono"
            value={code}
            inputMode="numeric"
            placeholder="000000"
            onChange={(event) => setCode(event.target.value)}
          />
          {problem ? <Notice tone="critical">{problem}</Notice> : null}
        </div>
        <div className="modal-foot">
          <button
            className="btn btn-primary"
            disabled={busy || code.length < 6}
            onClick={() =>
              run(async () => {
                await api.post('/api/v1/auth/elevate', { code });
                setElevating(false);
                setCode('');
                return { message: 'You are now at STRONG authentication.' };
              })
            }
          >
            Verify
          </button>
          <button className="btn btn-ghost" onClick={() => setElevating(false)}>
            Cancel
          </button>
        </div>
      </Modal>
    </>
  );
}
