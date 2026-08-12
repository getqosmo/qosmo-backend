'use client';

/**
 * The notifications bell.
 *
 * Restrained on purpose. MyBot's whole proposition is *less* mental load, so a
 * permanent red badge counting things at you would be working against the
 * product. The badge appears only when something is unread, the panel closes
 * on outside click, and opening it marks everything read — because a list you
 * have looked at is not a list of outstanding work.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { api } from '@/lib/api';
import type { NotificationItem } from '@/lib/api';
import { relativeDays } from './ui';

interface Payload {
  items: NotificationItem[];
  unread: number;
}

export function NotificationBell() {
  const [data, setData] = useState<Payload>({ items: [], unread: 0 });
  const [open, setOpen] = useState(false);
  const panel = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.get<Payload>('/api/v1/notifications?limit=30'));
    } catch {
      /* a failed poll is not worth surfacing */
    }
  }, []);

  useEffect(() => {
    void load();
    // Polled rather than pushed. Server-sent events are the right answer and
    // are roadmap work; a 60-second poll is honest and costs nothing.
    const timer = setInterval(load, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const onClick = (event: MouseEvent) => {
      if (panel.current && !panel.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next && data.unread > 0) {
      await api.post('/api/v1/notifications/read-all', {});
      setData((prev) => ({ ...prev, unread: 0 }));
    }
  }

  return (
    <div className="notif" ref={panel}>
      <button className="notif-trigger" onClick={toggle} aria-label="Notifications">
        <BellIcon />
        <span>Notifications</span>
        {data.unread > 0 ? <span className="nav-count">{data.unread}</span> : null}
      </button>

      {open ? (
        <div className="notif-panel">
          {data.items.length === 0 ? (
            <p className="small muted" style={{ padding: '14px 16px' }}>
              Nothing yet. MyBot will tell you when something needs you.
            </p>
          ) : (
            data.items.map((item) => (
              <div key={item.id} className="notif-item" data-urgency={item.urgency}>
                <div className="notif-title">{item.title}</div>
                <div className="notif-body">{item.body}</div>
                <div className="notif-meta">{relativeDays(item.created_at)}</div>
              </div>
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}

function BellIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
