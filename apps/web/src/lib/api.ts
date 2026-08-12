/**
 * API client.
 *
 * Two deliberate choices:
 *
 * 1. The session token lives in `sessionStorage`, not `localStorage`. It dies
 *    with the tab, which is the right default for something holding a
 *    person's entire life. A production deployment should move to an
 *    httpOnly, SameSite=Strict cookie so XSS cannot read it at all; that is
 *    noted in SECURITY.md as a known limitation of this build.
 *
 * 2. Errors are surfaced with their reasons intact. When the policy engine
 *    refuses something, the user should see *why* — "amount exceeds the
 *    $600 limit you set" — not a generic failure.
 */

const BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000';

const TOKEN_KEY = 'mybot.session';

export class ApiError extends Error {
  status: number;
  reasons: string[];

  constructor(message: string, status: number, reasons: string[] = []) {
    super(message);
    this.status = status;
    this.reasons = reasons;
  }
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return window.sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof window === 'undefined') return;
  if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
  else window.sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...((options.headers as Record<string, string>) ?? {}),
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, { ...options, headers });
  } catch {
    throw new ApiError(
      'MyBot is not reachable. Is the API running on ' + BASE + '?',
      0,
    );
  }

  if (response.status === 401) {
    setToken(null);
    throw new ApiError('Your session ended. Sign in again.', 401);
  }

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    let reasons: string[] = [];
    try {
      const body = await response.json();
      const detail = body?.detail;
      if (typeof detail === 'string') {
        message = detail;
      } else if (detail && typeof detail === 'object') {
        message = detail.message ?? message;
        reasons = detail.reasons ?? [];
        if (detail.what_exists) reasons.push(detail.what_exists);
      }
    } catch {
      /* keep the generic message */
    }
    throw new ApiError(message, response.status, reasons);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'PATCH',
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

// ---------------------------------------------------------------------------
// Types mirroring the API serialisers
// ---------------------------------------------------------------------------

export type Urgency = 'critical' | 'high' | 'medium' | 'low' | 'none';
export type Risk = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * An action a card offers.
 *
 * `params` is built by the server, never by the browser: an approval is bound
 * to a hash of exactly these values, so they must come from somewhere MyBot
 * controls. When MyBot cannot construct a valid action it says so in
 * `unavailable_reason` rather than offering something that will fail.
 */
export interface PossibleAction {
  label: string;
  action_type: string;
  requires_approval?: boolean;
  available?: boolean;
  unavailable_reason?: string;
  params?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

export interface InboxItem {
  id: string;
  category: string;
  urgency: Urgency;
  priority_score: number;
  state: string;
  title: string;
  explanation: string;
  reason: string | null;
  confidence: number;
  rule_id: string;
  source_ids: string[];
  evidence: Array<Record<string, unknown>>;
  possible_actions: PossibleAction[];
  recommended_action: string | null;
  obligation_id: string | null;
  entity_id: string | null;
  action_proposal_id: string | null;
  due_at: string | null;
  created_at: string;
}

export interface BriefLine {
  text: string;
  source_kind: string;
  source_id: string | null;
  detail: Record<string, unknown>;
}

export interface Brief {
  brief_date: string;
  greeting: string;
  summary: string;
  needs_you: BriefLine[];
  handled: BriefLine[];
  schedule: BriefLine[];
  closing: string;
  coverage: Record<string, { ok: boolean; reason?: string }>;
}

export interface TodayResponse {
  brief: Brief;
  needs_attention_count: number;
  items: InboxItem[];
  counts: Record<string, number>;
  coverage: Record<string, { ok: boolean; reason?: string }>;
}

/**
 * Human-readable rendering of what an action will do.
 *
 * Computed by the API from the proposal's parameters and the records they
 * reference — never assembled here. Displaying something the parameters do not
 * say would let a caller show one thing and do another.
 */
export interface ActionSummary {
  kind: 'calendar' | 'email' | 'payment' | 'obligation';
  subject?: string;
  from_label?: string;
  from_value?: string;
  to_label?: string;
  to_value?: string;
  location?: string | null;
  shift_days?: number;
  to?: string[];
  body?: string;
  amount?: number;
  currency?: string;
  payee?: string | null;
  account_ref?: string | null;
  memo?: string | null;
}

export interface ActionProposal {
  id: string;
  action_type: string;
  display: string;
  reversible: boolean;
  external: boolean;
  integration: string | null;
  params: Record<string, unknown>;
  status: string;
  risk: Risk;
  base_risk: Risk;
  requested_by: { type: string; id: string | null; label: string };
  reason: string | null;
  source_ids: string[];
  confidence: number;
  derived_from_untrusted: boolean;
  untrusted_source_ids: string[];
  requires_approval: boolean;
  required_auth_level: string;
  policy: { outcome: string | null; rule_id: string | null; reasons: string[] };
  execution: {
    outcome: string | null;
    result: { message?: string; simulated?: boolean } | null;
    error: string | null;
    executed_at: string | null;
  };
  created_at: string;
  summary?: ActionSummary | null;
  audit?: Array<{
    sequence: number;
    timestamp: string;
    event_type: string;
    result: string | null;
    reason: string | null;
    actor: string;
  }>;
}

export interface Entity {
  id: string;
  type: string;
  name: string;
  summary: string | null;
  attributes: Record<string, unknown>;
  aliases: string[];
  classification: string;
  confidence: number;
  source: { kind: string; id: string | null; detail: string | null; inferred: boolean };
  archived: boolean;
  facts?: Fact[];
  relationships?: Array<{
    id: string;
    type: string;
    direction: string;
    other: { id: string; name: string; type: string };
  }>;
}

export interface Fact {
  id: string;
  key: string;
  value: unknown;
  confidence: number;
  evidence: string | null;
  source: { kind: string; id: string | null; inferred: boolean };
  observed_at: string;
  superseded: boolean;
}

export interface Memory {
  id: string;
  kind: string;
  subject: string | null;
  content: string;
  structured: Record<string, unknown>;
  classification: string;
  source: { kind: string; inferred: boolean };
  created_at: string;
}

export interface Obligation {
  id: string;
  title: string;
  kind: string;
  status: string;
  due_at: string | null;
  amount: number | null;
  consequence: string | null;
  confidence: number;
  source: { kind: string; detail: string | null; ids: string[] };
}

export interface SecurityOverview {
  lockdown: {
    locked: boolean;
    locked_at: string | null;
    reason: string | null;
    automations_enabled: boolean;
    unlock_requires: string;
  };
  summary: {
    can_act_without_asking: number;
    standing_permissions: number;
    high_risk_permissions: number;
    connected_services: number;
    trusted_devices: number;
    active_automations: number;
    pending_approvals: number;
  };
  devices: Array<{
    id: string;
    name: string;
    kind: string;
    trusted: boolean;
    last_seen_at: string | null;
    revoked: boolean;
  }>;
  integrations: Array<{
    id: string;
    provider: string;
    display_name: string;
    status: string;
    scopes: string[];
    write_enabled: boolean;
    simulated: boolean;
    last_sync_at: string | null;
  }>;
  permissions: Array<{
    id: string;
    action_type: string;
    display: string;
    risk: Risk;
    description: string | null;
    max_amount: number | null;
    allowed_recipients: string[];
    requires_confirmation: boolean;
    requires_strong_auth: boolean;
    allow_automatic: boolean;
    expires_at: string | null;
  }>;
  automations: Array<{
    id: string;
    name: string;
    description: string | null;
    enabled: boolean;
    trigger_type: string;
  }>;
  recent_actions: Array<{
    id: string;
    display: string;
    status: string;
    risk: Risk;
    requested_by: string;
    created_at: string;
    outcome: string | null;
    derived_from_untrusted: boolean;
  }>;
  security_events: Array<{
    id: string;
    type: string;
    severity: string;
    summary: string;
    created_at: string;
  }>;
  model_routing: Record<string, unknown>;
  vault: Record<string, unknown>;
  audit: { ok: boolean; events_checked: number; problem: string | null };
}

export interface ChatAnswer {
  text: string;
  conversation_id: string;
  citations: string[];
  grounded_only: boolean;
  model_used: string | null;
  unavailable: string[];
  structured: Record<string, unknown> | null;
}

export interface Me {
  id: string;
  email: string;
  display_name: string;
  auth_level: string;
  is_demo: boolean;
}
