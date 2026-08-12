'use client';

/**
 * OAuth return leg.
 *
 * The provider sends the browser back here with `code` and `state`. This page
 * hands both to the API, which verifies the state against a live record bound
 * to the *authenticated* owner before exchanging anything.
 *
 * Note what this page does not do: it never sees a token. The exchange happens
 * server-side, the refresh token goes into the Vault, and the browser gets back
 * only the scopes that were granted. A page that received a token in a URL
 * fragment would be putting it in browser history.
 */

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense } from 'react';

import { ApiError, api } from '@/lib/api';
import { Notice } from '@/components/ui';

function Callback() {
  const params = useSearchParams();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ display_name: string; scopes: string[] } | null>(null);

  useEffect(() => {
    const code = params.get('code');
    const state = params.get('state');
    const denied = params.get('error');

    if (denied) {
      // The owner said no at the consent screen. That is a normal outcome, not
      // an error to apologise for.
      setError('Sign-in was cancelled. Nothing was connected.');
      return;
    }
    if (!code || !state) {
      setError('That link was incomplete. Start again from Connected accounts.');
      return;
    }

    api
      .post<{ display_name: string; scopes: string[] }>('/api/v1/integrations/callback', {
        state,
        code,
      })
      .then(setDone)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : 'Could not finish connecting.'),
      );
  }, [params]);

  return (
    <>
      <header className="page-header">
        <h1>Connecting your account</h1>
      </header>

      {error ? (
        <>
          <Notice tone="critical">{error}</Notice>
          <div className="btn-row mt-2">
            <button className="btn btn-sm" onClick={() => router.push('/connect')}>
              Back to Connected accounts
            </button>
          </div>
        </>
      ) : done ? (
        <>
          <Notice tone="info">
            <strong>{done.display_name} is connected, read-only.</strong> MyBot can now see what
            you granted and nothing more.
          </Notice>
          <div className="card mt-2">
            <div className="section-label" style={{ marginTop: 0 }}>
              What you granted
            </div>
            <ul style={{ margin: '8px 0 0', paddingLeft: '1.1rem' }}>
              {done.scopes.map((scope) => (
                <li key={scope} className="secondary mono" style={{ fontSize: '0.82rem' }}>
                  {scope}
                </li>
              ))}
            </ul>
          </div>
          <div className="btn-row mt-2">
            <button className="btn btn-sm btn-primary" onClick={() => router.push('/connect')}>
              Done
            </button>
          </div>
        </>
      ) : (
        <p className="secondary">Finishing up…</p>
      )}
    </>
  );
}

export default function CallbackPage() {
  return (
    <Suspense fallback={<p className="secondary">Loading…</p>}>
      <Callback />
    </Suspense>
  );
}
