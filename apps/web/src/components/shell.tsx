'use client';

/**
 * Application shell: navigation, session bootstrap, and the login screen.
 *
 * The nav order is the product's order of importance: TODAY first, chat
 * fourth. MyBot is not a chatbot with a dashboard bolted on, and the
 * navigation should say so.
 *
 * It is split into two groups rather than one flat list, because a flat list
 * of nine is a wall — everything shouts equally and the eye has nowhere to
 * land. The top four are the surfaces somebody opens daily. The rest are
 * where you go to *check on* MyBot: what it can do, what it has learned, what
 * has left the machine. Both matter; only one of them is a daily habit.
 */

import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

import { ApiError, api, hasSession } from '@/lib/api';
import { LogoMark, TAGLINE } from './brand';
import type { Me } from '@/lib/api';
import { NotificationBell } from './notifications';
import { Notice, Spinner } from './ui';

/** What you open every day. */
const NAV = [
  { href: '/', label: 'Today' },
  { href: '/inbox', label: 'Inbox' },
  { href: '/ask', label: 'Ask' },
  { href: '/life', label: 'Life' },
];

/** Where you go to check on MyBot rather than to use it. */
const NAV_TRUST = [
  { href: '/security', label: 'What it can do' },
  { href: '/growth', label: 'What it has learned' },
  { href: '/egress', label: 'What has left' },
  { href: '/automations', label: 'Standing rules' },
  { href: '/connect', label: 'Connected accounts' },
  { href: '/vault', label: 'Documents & keys' },
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
    // A hint, not an authorisation check -- the session cookie is httpOnly and
    // invisible here, so this only avoids a pointless 401 on first paint.
    if (!hasSession()) {
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
    // The server revokes the session and clears the cookies; there is nothing
    // for the browser to forget on its own.
    void api.post('/api/v1/auth/logout').catch(() => undefined);
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
          <div className="nav-group-label">Keeping MyBot honest</div>
          <nav className="nav nav-secondary">
            {NAV_TRUST.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="nav-link"
                data-active={pathname.startsWith(item.href)}
              >
                <span>{item.label}</span>
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
      // The response carries a token for non-browser callers; this app
      // deliberately ignores it and relies on the httpOnly cookie the server
      // set, which JavaScript here cannot read.
      await api.post('/api/v1/auth/login', {
        email,
        password,
        device_name: 'Browser',
      });
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
