'use client';

/**
 * CONNECT — external accounts.
 *
 * The screen where somebody hands MyBot reach into their real life, so it is
 * written to slow that down rather than speed it up.
 *
 * Three things it does differently from a normal integrations page:
 *
 * **It shows the scopes before you leave.** The provider's consent screen
 * should not be the first time you learn what is being asked for.
 *
 * **It connects read-only.** Permission to send or change anything is a
 * separate, later decision, offered only once there is something to judge it
 * against.
 *
 * **It says what disconnecting actually does.** "Revokes at Google, then
 * deletes locally" is a real promise about ordering, and a user deciding
 * whether to connect deserves to know the exit exists before they take the
 * entrance.
 */

import { useState } from 'react';

import { ApiError, api } from '@/lib/api';
import { Badge, Notice, useAsync } from '@/components/ui';

interface Provider {
  key: string;
  display_name: string;
  read_scopes: string[];
  write_scopes: string[];
  connected: boolean;
}

interface ProvidersResponse {
  providers: Provider[];
  configured: boolean;
  note: string;
}

/** Turn a Google scope URL into something a person can weigh. */
const SCOPE_PLAIN: Record<string, string> = {
  'https://www.googleapis.com/auth/calendar.readonly': 'Read your calendar events',
  'https://www.googleapis.com/auth/calendar.events': 'Create and change calendar events',
  'https://www.googleapis.com/auth/gmail.readonly': 'Read your email',
  'https://www.googleapis.com/auth/gmail.compose': 'Draft emails',
  'https://www.googleapis.com/auth/gmail.modify': 'Label and archive email',
};

function plainScope(scope: string): string {
  return SCOPE_PLAIN[scope] ?? scope.replace(/^https:\/\/www\.googleapis\.com\/auth\//, '');
}

export default function ConnectPage() {
  const providers = useAsync<ProvidersResponse>(
    () => api.get<ProvidersResponse>('/api/v1/integrations/providers'),
    [],
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function connect(provider: Provider) {
    setBusy(provider.key);
    setError(null);
    try {
      const started = await api.post<{ authorization_url: string }>(
        '/api/v1/integrations/connect',
        {
          provider: provider.key,
          redirect_uri: `${window.location.origin}/integrations/callback`,
          include_write: false,
        },
      );
      window.location.href = started.authorization_url;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not start sign-in.');
      setBusy(null);
    }
  }

  async function disconnect(provider: Provider) {
    setBusy(provider.key);
    setError(null);
    try {
      await api.delete(`/api/v1/integrations/${provider.key}`);
      providers.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not disconnect.');
    } finally {
      setBusy(null);
    }
  }

  const data = providers.data;

  return (
    <>
      <header className="page-header">
        <h1>Connected accounts</h1>
        <p className="page-subtitle">
          MyBot connects read-only. Permission to send or change anything is a separate
          decision you make later, once you have seen how it behaves.
        </p>
      </header>

      {error ? <Notice tone="critical">{error}</Notice> : null}

      {data && !data.configured ? (
        <div className="mb-3">
          <Notice tone="info">
            <strong>No OAuth client is configured on this MyBot.</strong> Connecting a real
            account needs your own Google client credentials in{' '}
            <span className="mono">MYBOT_GOOGLE_CLIENT_ID</span> and{' '}
            <span className="mono">MYBOT_GOOGLE_CLIENT_SECRET</span>. Nothing ships with the
            product — a shared client id would mean every installation used one identity at
            the provider. Until then MyBot runs on simulated connectors.
          </Notice>
        </div>
      ) : null}

      {providers.loading ? <p className="secondary">Loading…</p> : null}

      {data?.providers.map((provider) => (
        <div className="card mb-2" key={provider.key}>
          <div className="card-head">
            <span className="list-title">{provider.display_name}</span>
            <div className="spacer" />
            {provider.connected ? (
              <Badge tone="success">Connected</Badge>
            ) : (
              <Badge tone="neutral">Not connected</Badge>
            )}
          </div>

          <div className="card-body mt-1">
            <div className="section-label" style={{ marginTop: 12 }}>
              What it would be allowed to do
            </div>
            <ul className="mt-1" style={{ margin: 0, paddingLeft: '1.1rem' }}>
              {provider.read_scopes.map((scope) => (
                <li key={scope} className="secondary">
                  {plainScope(scope)}
                </li>
              ))}
            </ul>

            {provider.write_scopes.length > 0 ? (
              <p className="secondary mt-2">
                Not requested now: {provider.write_scopes.map(plainScope).join(', ').toLowerCase()}.
                MyBot will ask separately if you ever want that.
              </p>
            ) : null}
          </div>

          <div className="btn-row mt-2">
            {provider.connected ? (
              <button
                className="btn btn-sm btn-ghost"
                disabled={busy === provider.key}
                onClick={() => disconnect(provider)}
              >
                Disconnect
              </button>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                disabled={busy === provider.key || !data.configured}
                onClick={() => connect(provider)}
              >
                Connect read-only
              </button>
            )}
          </div>
        </div>
      ))}

      <p className="secondary mt-3">
        Disconnecting revokes access at the provider first, then deletes the credential here.
        That order matters: the other way round would leave a live grant on their side that you
        could no longer see or revoke from MyBot. Everything a connected account does shows up
        in <span className="mono">What has left</span>.
      </p>
    </>
  );
}
