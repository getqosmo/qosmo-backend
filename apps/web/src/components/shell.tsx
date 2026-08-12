'use client';

/**
 * Application shell: navigation, session bootstrap, and the login screen.
 *
 * The nav order is the product's order of importance: TODAY first, chat
 * fourth. MyBot is not a chatbot with a dashboard bolted on, and the
 * navigation should say so.
 */

import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

import { ApiError, api, getToken, setToken } from '@/lib/api';
import { LogoMark, TAGLINE } from './brand';
import type { Me } from '@/lib/api';
import { NotificationBell } from './notifications';
import { Notice, Spinner } from './ui';

const NAV = [
  { href: '/', label: 'Today' },
  { href: '/inbox', label: 'Inbox' },
  { href: '/ask', label: 'Ask' },
  { href: '/life', label: 'Life' },
  { href: '/automations', label: 'Automations' },
  { href: '/vault', label: 'Vault' },
  { href: '/security', label: 'Security' },
];

interface SessionValue {
  me: Me | null;
  refresh: () => Promise<void>;
  signOut: () => void;
  pending: number;
  setPending: (n: number) => void;
}

const SessionContext = createContext<SessionValue>({
  me: null,
  refresh: async () => {},
  signOut: () => {},
  pending: 0,
  setPending: () => {},
});

export const useSession = () => useContext(SessionContext);

export function AppShell({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState(0);
  const pathname = usePathname();

  const refresh = useCallback(async () => {
    if (!getToken()) {
      setMe(null);
      setReady(true);
      return;
    }
    try {
      setMe(await api.get<Me>('/api/v1/auth/me'));
    } catch {
      setMe(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signOut = useCallback(() => {
    void api.post('/api/v1/auth/logout').catch(() => undefined);
    setToken(null);
    setMe(null);
  }, []);

  if (!ready) {
    return (
      <div className="auth-shell">
        <Spinner />
      </div>
    );
  }

  if (!me) {
    return <SignIn onSignedIn={refresh} />;
  }

  return (
    <SessionContext.Provider value={{ me, refresh, signOut, pending, setPending }}>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <LogoMark size={26} />
            <div className="brand-name">MyBot</div>
          </div>
          <nav className="nav">
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="nav-link"
                data-active={
                  item.href === '/'
                    ? pathname === '/'
                    : pathname.startsWith(item.href)
                }
              >
                <span>{item.label}</span>
                {item.href === '/inbox' && pending > 0 ? (
                  <span className="nav-count">{pending}</span>
                ) : null}
              </Link>
            ))}
          </nav>
          <NotificationBell />
          <div className="sidebar-footer">
            <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
              {me.display_name}
            </div>
            <div className="small">{me.email}</div>
            <button
              className="btn btn-ghost btn-sm"
              style={{ marginTop: 8, paddingLeft: 0 }}
              onClick={signOut}
            >
              Sign out
            </button>
          </div>
        </aside>
        <main className="main">
          <div className="container">{children}</div>
        </main>
      </div>
    </SessionContext.Provider>
  );
}

// ---------------------------------------------------------------------------

function SignIn({ onSignedIn }: { onSignedIn: () => Promise<void> }) {
  const [email, setEmail] = useState('alex@example.com');
  const [password, setPassword] = useState('demo-password-1234');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const router = useRouter();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ access_token: string }>(
        '/api/v1/auth/login',
        { email, password, device_name: 'Browser' },
      );
      setToken(result.access_token);
      await onSignedIn();
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">
          <LogoMark size={34} />
          <div className="brand-name" style={{ fontSize: 18 }}>
            MyBot
          </div>
        </div>
        <h1 style={{ fontSize: 22, marginBottom: 8 }}>{TAGLINE}</h1>
        <p className="auth-tagline" style={{ marginTop: 8 }}>
          Sign in to your MyBot.
        </p>

        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            className="input"
            type="email"
            value={email}
            autoComplete="username"
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            className="input"
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {error ? <Notice tone="critical">{error}</Notice> : null}

        <button className="btn btn-primary" style={{ width: '100%' }} disabled={busy}>
          {busy ? <Spinner /> : null} Sign in
        </button>

        <p className="small muted mt-2" style={{ textAlign: 'center' }}>
          Demo account is pre-filled. Run <span className="mono">mybot demo</span> to
          create it.
        </p>
      </form>
    </div>
  );
}
