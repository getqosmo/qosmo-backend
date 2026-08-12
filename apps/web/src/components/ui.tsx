'use client';

/**
 * Shared UI primitives.
 *
 * The approval components are the ones that matter most. The product spec is
 * explicit that MyBot must never show "Confirm? Yes/No" — an approval has to
 * show what, from what, to what, why, who asked, and at what risk. That
 * requirement is encoded here so no screen can accidentally render a bare
 * confirmation dialog.
 */

import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';

import type { ActionProposal, ActionSummary, Risk, Urgency } from '@/lib/api';

// ---------------------------------------------------------------------------

export function Badge({
  tone = 'neutral',
  children,
}: {
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'neutral' | 'info' | 'success' | 'accent';
  children: ReactNode;
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

const RISK_TONE: Record<Risk, 'low' | 'medium' | 'high' | 'critical'> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

export function RiskBadge({ risk }: { risk: Risk }) {
  return <Badge tone={RISK_TONE[risk]}>{risk} risk</Badge>;
}

const URGENCY_TONE: Record<Urgency, 'critical' | 'high' | 'medium' | 'low' | 'neutral'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  none: 'neutral',
};

export function UrgencyBadge({ urgency }: { urgency: Urgency }) {
  if (urgency === 'none') return null;
  return <Badge tone={URGENCY_TONE[urgency]}>{urgency}</Badge>;
}

export function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

export function Empty({ title, body }: { title: string; body?: string }) {
  return (
    <div className="empty">
      <div className="empty-title">{title}</div>
      {body ? <div className="small">{body}</div> : null}
    </div>
  );
}

export function Notice({
  tone = 'default',
  children,
}: {
  tone?: 'default' | 'warning' | 'critical' | 'info';
  children: ReactNode;
}) {
  const cls = tone === 'default' ? 'notice' : `notice notice-${tone}`;
  return <div className={cls}>{children}</div>;
}

export function Modal({
  open,
  onClose,
  children,
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div className="modal" onClick={(event) => event.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------

/**
 * Renders a before/after transition, e.g. Tuesday 2:00 PM → Thursday 3:15 PM.
 */
export function Transition({
  fromLabel,
  from,
  toLabel,
  to,
}: {
  fromLabel: string;
  from: string;
  toLabel: string;
  to: string;
}) {
  return (
    <div className="transition">
      <div className="transition-side">
        <div className="transition-label">{fromLabel}</div>
        <div className="transition-value">{from}</div>
      </div>
      <div className="transition-arrow" aria-hidden>
        →
      </div>
      <div className="transition-side">
        <div className="transition-label">{toLabel}</div>
        <div className="transition-value">{to}</div>
      </div>
    </div>
  );
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString(undefined, {
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  });
}

export function relativeDays(value: string | null | undefined): string {
  if (!value) return '';
  const days = Math.round(
    (new Date(value).getTime() - Date.now()) / 86_400_000,
  );
  if (Number.isNaN(days)) return '';
  if (days < 0) return `${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago`;
  if (days === 0) return 'today';
  if (days === 1) return 'tomorrow';
  return `in ${days} days`;
}

/**
 * The approval sheet.
 *
 * Deliberately verbose. Every element here exists because approving without
 * it would mean consenting to something you cannot see: the exact change, the
 * stated reason, which subsystem asked, the risk class, whether the action is
 * reversible, and — critically — a warning when the proposal originated from
 * content a stranger controls.
 */
export function ApprovalSheet({
  action,
  onApprove,
  onReject,
  onClose,
  busy,
  error,
  authLevel,
}: {
  action: ActionProposal;
  onApprove: () => void;
  onReject: () => void;
  onClose: () => void;
  busy: boolean;
  error: string | null;
  authLevel: string;
}) {
  const needsStrong =
    action.required_auth_level === 'STRONG' || action.required_auth_level === 'PHYSICAL';
  const hasStrong = authLevel === 'STRONG' || authLevel === 'PHYSICAL';
  const blocked = needsStrong && !hasStrong;

  return (
    <>
      <div className="modal-head">
        <div className="row mb-1">
          <Badge tone="accent">MyBot wants to</Badge>
          <RiskBadge risk={action.risk} />
          {!action.reversible ? <Badge tone="high">Cannot be undone</Badge> : null}
        </div>
        <h2>{action.display}</h2>
      </div>

      <div className="modal-body">
        {action.derived_from_untrusted ? (
          <Notice tone="warning">
            This was suggested based on content from outside MyBot (an email or
            a document). Treat it with extra care — MyBot has already refused to
            let untrusted content reach anything higher risk.
          </Notice>
        ) : null}

        <ActionDetail action={action} />

        {action.reason ? (
          <>
            <div className="section-label">Reason</div>
            <p className="secondary">{action.reason}</p>
          </>
        ) : null}

        <div className="section-label">Details</div>
        <div className="detail-row">
          <span className="detail-key">Requested by</span>
          <span className="detail-value">{action.requested_by.label}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Confidence</span>
          <span className="detail-value">{Math.round(action.confidence * 100)}%</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Authentication required</span>
          <span className="detail-value">{action.required_auth_level}</span>
        </div>
        {action.integration ? (
          <div className="detail-row">
            <span className="detail-key">Will be carried out by</span>
            <span className="detail-value">{action.integration}</span>
          </div>
        ) : null}
        {action.policy.rule_id ? (
          <div className="detail-row">
            <span className="detail-key">Permitted by</span>
            <span className="detail-value mono">{action.policy.rule_id.slice(0, 8)}</span>
          </div>
        ) : null}

        {action.policy.reasons.length ? (
          <>
            <div className="section-label">Why approval is needed</div>
            <ul className="small secondary" style={{ margin: 0, paddingLeft: 18 }}>
              {action.policy.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          </>
        ) : null}

        {blocked ? (
          <Notice tone="warning">
            This action needs {action.required_auth_level} authentication.
            Verify your second factor in Security before approving.
          </Notice>
        ) : null}

        {error ? <Notice tone="critical">{error}</Notice> : null}
      </div>

      <div className="modal-foot">
        <button
          className="btn btn-primary"
          onClick={onApprove}
          disabled={busy || blocked}
        >
          {busy ? <Spinner /> : null} Approve
        </button>
        <button className="btn" onClick={onReject} disabled={busy}>
          Reject
        </button>
        <div className="spacer" />
        <button className="btn btn-ghost" onClick={onClose} disabled={busy}>
          Cancel
        </button>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------

/**
 * Renders what the action will actually do.
 *
 * Prefers the server-computed summary. Falls back to the raw parameters rather
 * than showing nothing — an approval with no visible detail is exactly the
 * "Confirm? Yes/No" pattern this product must not ship.
 */
function ActionDetail({ action }: { action: ActionProposal }) {
  const summary = action.summary as ActionSummary | null | undefined;

  if (!summary) {
    const entries = Object.entries(action.params ?? {});
    if (!entries.length) return null;
    return (
      <div className="card mt-2 mb-2">
        {entries.map(([key, value]) => (
          <div key={key} className="detail-row">
            <span className="detail-key">{key.replace(/_/g, ' ')}</span>
            <span className="detail-value">
              {Array.isArray(value) ? value.join(', ') : String(value ?? '—')}
            </span>
          </div>
        ))}
      </div>
    );
  }

  if (summary.kind === 'payment') {
    return (
      <div className="card mt-2 mb-2">
        <div className="stat-value">
          ${Number(summary.amount ?? 0).toLocaleString(undefined, {
            minimumFractionDigits: 2,
          })}
        </div>
        <div className="detail-row mt-1">
          <span className="detail-key">Recipient</span>
          <span className="detail-value">{summary.payee ?? '—'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Account</span>
          <span className="detail-value mono">{summary.account_ref ?? '—'}</span>
        </div>
        {summary.memo ? (
          <div className="detail-row">
            <span className="detail-key">Reference</span>
            <span className="detail-value">{summary.memo}</span>
          </div>
        ) : null}
      </div>
    );
  }

  if (summary.kind === 'email') {
    return (
      <div className="card mt-2 mb-2">
        <div className="detail-row">
          <span className="detail-key">To</span>
          <span className="detail-value">{(summary.to ?? []).join(', ') || '—'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Subject</span>
          <span className="detail-value">{summary.subject}</span>
        </div>
        <div className="mt-2 small secondary" style={{ whiteSpace: 'pre-wrap' }}>
          {summary.body}
        </div>
      </div>
    );
  }

  return (
    <>
      {summary.subject ? (
        <div className="card-title mt-2" style={{ fontSize: 16 }}>
          {summary.subject}
        </div>
      ) : null}
      <Transition
        fromLabel={summary.from_label ?? 'Currently'}
        from={summary.from_value ?? '—'}
        toLabel={summary.to_label ?? 'Change to'}
        to={summary.to_value ?? '—'}
      />
      {summary.location ? (
        <p className="small muted" style={{ marginTop: -6 }}>
          {summary.location}
        </p>
      ) : null}
    </>
  );
}

export function useAsync<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    loader()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, error, loading, reload: () => setNonce((n) => n + 1) };
}
