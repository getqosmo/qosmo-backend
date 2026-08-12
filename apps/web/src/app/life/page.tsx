'use client';

/**
 * LIFE — everything MyBot knows, and all of it editable.
 *
 * Grouped the way a person thinks about their life rather than the way the
 * database stores it. Each record shows where it came from and how confident
 * MyBot is, because "what does it know about me, and why does it think that?"
 * has to be answerable without reading a log.
 */

import { useState } from 'react';

import { api } from '@/lib/api';
import type { Entity, Memory, Obligation } from '@/lib/api';
import {
  Badge,
  Empty,
  Modal,
  Notice,
  formatDate,
  relativeDays,
  useAsync,
} from '@/components/ui';

const GROUPS: Array<{ label: string; types: string[] }> = [
  { label: 'People', types: ['Person'] },
  { label: 'Money', types: ['Bill', 'Subscription', 'Account', 'Purchase'] },
  { label: 'Home', types: ['Property', 'ServiceProvider'] },
  { label: 'Vehicles', types: ['Vehicle'] },
  { label: 'Documents', types: ['Document'] },
  { label: 'Work', types: ['Organization', 'Project'] },
  { label: 'Travel', types: ['Trip'] },
];

interface EntitiesResponse {
  items: Entity[];
  counts: Record<string, number>;
}
interface MemoryResponse {
  items: Memory[];
  preferences: Record<string, unknown>;
}
interface ObligationsResponse {
  items: Obligation[];
}

export default function LifePage() {
  const entities = useAsync<EntitiesResponse>(
    () => api.get<EntitiesResponse>('/api/v1/entities?limit=500'),
    [],
  );
  const memories = useAsync<MemoryResponse>(
    () => api.get<MemoryResponse>('/api/v1/memory'),
    [],
  );
  const obligations = useAsync<ObligationsResponse>(
    () => api.get<ObligationsResponse>('/api/v1/obligations'),
    [],
  );
  const [selected, setSelected] = useState<Entity | null>(null);
  const [newMemory, setNewMemory] = useState('');

  if (entities.loading) return <div className="skeleton" style={{ height: 320 }} />;
  if (entities.error) return <Notice tone="critical">{entities.error}</Notice>;

  const all = entities.data?.items ?? [];
  const open = (obligations.data?.items ?? []).filter(
    (item) => !['done', 'cancelled'].includes(item.status),
  );

  async function openEntity(id: string) {
    setSelected(await api.get<Entity>(`/api/v1/entities/${id}`));
  }

  return (
    <>
      <header className="page-header">
        <h1>Your life</h1>
        <p className="page-subtitle">
          Everything MyBot knows. All of it is yours to edit or delete.
        </p>
      </header>

      {open.length ? (
        <>
          <div className="section-label">Obligations</div>
          <div className="card">
            {open.map((item) => (
              <div key={item.id} className="list-row">
                <div className="list-main">
                  <div className="list-title">{item.title}</div>
                  <div className="list-sub">
                    {item.due_at
                      ? `${formatDate(item.due_at)} · ${relativeDays(item.due_at)}`
                      : 'No date'}
                    {item.amount ? ` · $${item.amount.toFixed(2)}` : ''}
                    {item.source.detail ? ` · ${item.source.detail}` : ''}
                  </div>
                </div>
                <div className="row">
                  {item.confidence < 0.9 ? (
                    <Badge tone="neutral">{Math.round(item.confidence * 100)}%</Badge>
                  ) : null}
                  <button
                    className="btn btn-sm"
                    onClick={async () => {
                      await api.post(`/api/v1/obligations/${item.id}/complete`, {});
                      obligations.reload();
                    }}
                  >
                    Done
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      ) : null}

      {GROUPS.map((group) => {
        const members = all.filter((entity) => group.types.includes(entity.type));
        if (!members.length) return null;
        return (
          <section key={group.label}>
            <div className="section-label">{group.label}</div>
            <div className="grid-2">
              {members.map((entity) => (
                <button
                  key={entity.id}
                  className="card card-interactive"
                  style={{ textAlign: 'left' }}
                  onClick={() => openEntity(entity.id)}
                >
                  <div className="card-title">{entity.name}</div>
                  <div className="small muted mt-1">
                    {entity.summary ?? entity.type}
                  </div>
                  {entity.classification !== 'PERSONAL' ? (
                    <div className="mt-1">
                      <Badge tone="neutral">{entity.classification}</Badge>
                    </div>
                  ) : null}
                </button>
              ))}
            </div>
          </section>
        );
      })}

      <div className="section-label">What MyBot remembers</div>
      <div className="card">
        <div className="row mb-2">
          <input
            className="input"
            placeholder="Tell MyBot something to remember…"
            value={newMemory}
            onChange={(event) => setNewMemory(event.target.value)}
          />
          <button
            className="btn btn-primary"
            disabled={!newMemory.trim()}
            onClick={async () => {
              await api.post('/api/v1/memory', { content: newMemory.trim() });
              setNewMemory('');
              memories.reload();
            }}
          >
            Remember
          </button>
        </div>
        {(memories.data?.items ?? []).length === 0 ? (
          <Empty title="Nothing remembered yet." />
        ) : (
          (memories.data?.items ?? []).map((memory) => (
            <div key={memory.id} className="list-row">
              <div className="list-main">
                <div className="list-title">{memory.content}</div>
                <div className="list-sub">
                  {memory.kind} · {memory.source.kind.replace(/_/g, ' ')} ·{' '}
                  {formatDate(memory.created_at)}
                  {Object.keys(memory.structured).length
                    ? ` · acts on: ${Object.entries(memory.structured)
                        .map(([key, value]) => `${key}=${String(value)}`)
                        .join(', ')}`
                    : ''}
                </div>
              </div>
              <button
                className="btn btn-sm btn-ghost"
                onClick={async () => {
                  await api.delete(`/api/v1/memory/${memory.id}`);
                  memories.reload();
                }}
              >
                Forget
              </button>
            </div>
          ))
        )}
      </div>

      <Modal open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? (
          <>
            <div className="modal-head">
              <div className="row mb-1">
                <Badge tone="neutral">{selected.type}</Badge>
                <Badge tone="neutral">{selected.classification}</Badge>
              </div>
              <h2>{selected.name}</h2>
            </div>
            <div className="modal-body">
              {selected.summary ? <p className="secondary">{selected.summary}</p> : null}

              {selected.facts?.length ? (
                <>
                  <div className="section-label">Known facts</div>
                  {selected.facts.map((fact) => (
                    <div key={fact.id} className="detail-row">
                      <span className="detail-key">{fact.key.replace(/_/g, ' ')}</span>
                      <span className="detail-value">
                        {String(fact.value)}
                        <div className="small muted">
                          {fact.source.kind.replace(/_/g, ' ')} ·{' '}
                          {Math.round(fact.confidence * 100)}%
                          {fact.evidence ? ` · “${fact.evidence}”` : ''}
                        </div>
                      </span>
                    </div>
                  ))}
                </>
              ) : null}

              {Object.keys(selected.attributes).length ? (
                <>
                  <div className="section-label">Attributes</div>
                  {Object.entries(selected.attributes)
                    .filter(([key]) => key !== 'possible_duplicate_of')
                    .map(([key, value]) => (
                      <div key={key} className="detail-row">
                        <span className="detail-key">{key.replace(/_/g, ' ')}</span>
                        <span className="detail-value">{String(value)}</span>
                      </div>
                    ))}
                </>
              ) : null}

              {selected.relationships?.length ? (
                <>
                  <div className="section-label">Connected to</div>
                  {selected.relationships.map((relationship) => (
                    <div key={relationship.id} className="detail-row">
                      <span className="detail-key">
                        {relationship.type.replace(/_/g, ' ').toLowerCase()}
                      </span>
                      <span className="detail-value">{relationship.other.name}</span>
                    </div>
                  ))}
                </>
              ) : null}

              <div className="section-label">Where this came from</div>
              <p className="small secondary">
                {selected.source.kind.replace(/_/g, ' ')}
                {selected.source.detail ? ` — ${selected.source.detail}` : ''}
                {selected.source.inferred ? ' (inferred)' : ''} ·{' '}
                {Math.round(selected.confidence * 100)}% confident
              </p>
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setSelected(null)}>
                Close
              </button>
              <div className="spacer" />
              <button
                className="btn btn-danger"
                onClick={async () => {
                  await api.delete(`/api/v1/entities/${selected.id}`);
                  setSelected(null);
                  entities.reload();
                }}
              >
                Archive
              </button>
            </div>
          </>
        ) : null}
      </Modal>
    </>
  );
}
