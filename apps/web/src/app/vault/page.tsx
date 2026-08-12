'use client';

/**
 * VAULT — documents and the credential store.
 *
 * Note what this screen does *not* do: it never shows a secret. The Vault
 * section describes how secrets are protected and what exists, because
 * "show me my passwords" is a feature request that should be declined by
 * design rather than implemented carefully.
 */

import { useRef, useState } from 'react';

import { ApiError, api } from '@/lib/api';
import type { SecurityOverview } from '@/lib/api';
import { Badge, Empty, Notice, Spinner, formatDate, useAsync } from '@/components/ui';

interface DocumentRecord {
  id: string;
  filename: string;
  document_type: string | null;
  issuer: string | null;
  folder: string;
  classification: string;
  extraction_status: string;
  extraction_error: string | null;
  fields: Array<{ field: string; value: string; confidence: number; evidence: string }>;
  created_at: string;
}

export default function VaultPage() {
  const documents = useAsync<{ items: DocumentRecord[] }>(
    () => api.get<{ items: DocumentRecord[] }>('/api/v1/documents'),
    [],
  );
  const overview = useAsync<SecurityOverview>(
    () => api.get<SecurityOverview>('/api/v1/security'),
    [],
  );
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  async function upload(file: File) {
    setUploading(true);
    setError(null);
    try {
      const body = new FormData();
      body.append('file', file);
      const token = window.sessionStorage.getItem('mybot.session');
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000'}/api/v1/documents`,
        {
          method: 'POST',
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          body,
        },
      );
      if (!response.ok) throw new ApiError('Upload failed', response.status);
      documents.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed.');
    } finally {
      setUploading(false);
    }
  }

  const vault = (overview.data?.vault ?? {}) as {
    keystore?: { backend?: string; hardware_backed?: boolean; note?: string };
    algorithm?: string;
    key_derivation?: string;
  };

  return (
    <>
      <header className="page-header">
        <h1>Vault</h1>
        <p className="page-subtitle">
          Your documents and credentials, encrypted on this machine.
        </p>
      </header>

      {error ? <Notice tone="critical">{error}</Notice> : null}

      <div className="card mb-2">
        <div className="row-between">
          <div>
            <div className="card-title">Add a document</div>
            <p className="small secondary mt-1">
              MyBot reads dates and amounts, records where each value came from,
              and tracks any deadline it finds. Files are encrypted at rest.
            </p>
          </div>
          <button
            className="btn btn-primary"
            disabled={uploading}
            onClick={() => fileInput.current?.click()}
          >
            {uploading ? <Spinner /> : null} Upload
          </button>
          <input
            ref={fileInput}
            type="file"
            hidden
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void upload(file);
            }}
          />
        </div>
      </div>

      <div className="section-label">Documents</div>
      {(documents.data?.items ?? []).length === 0 ? (
        <Empty title="No documents yet." body="Upload a bill, a registration or a policy." />
      ) : (
        (documents.data?.items ?? []).map((document) => (
          <article key={document.id} className="card">
            <div className="card-head">
              <Badge tone="neutral">
                {(document.document_type ?? 'document').replace(/_/g, ' ')}
              </Badge>
              <Badge
                tone={
                  document.classification === 'HIGHLY_SENSITIVE' ||
                  document.classification === 'SECRET'
                    ? 'high'
                    : 'neutral'
                }
              >
                {document.classification.replace(/_/g, ' ').toLowerCase()}
              </Badge>
              <div className="spacer" />
              <span className="small muted">{formatDate(document.created_at)}</span>
            </div>
            <div className="card-title">{document.filename}</div>
            {document.issuer ? (
              <p className="small secondary mt-1">Issued by {document.issuer}</p>
            ) : null}

            {document.extraction_error ? (
              <Notice tone="warning">{document.extraction_error}</Notice>
            ) : null}

            {document.fields.length ? (
              <div className="mt-2">
                {document.fields.map((field) => (
                  <div key={field.field} className="detail-row">
                    <span className="detail-key">{field.field.replace(/_/g, ' ')}</span>
                    <span className="detail-value">
                      {field.value}
                      <div className="small muted">
                        {Math.round(field.confidence * 100)}% · “{field.evidence}”
                      </div>
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
          </article>
        ))
      )}

      <div className="section-label">How your secrets are protected</div>
      <div className="card">
        <div className="detail-row">
          <span className="detail-key">Encryption</span>
          <span className="detail-value">{vault.algorithm ?? 'AES-256-GCM'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Key derivation</span>
          <span className="detail-value">{vault.key_derivation ?? 'HKDF-SHA256'}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Key storage</span>
          <span className="detail-value">
            {vault.keystore?.backend ?? 'software'}
            {vault.keystore?.hardware_backed ? ' (hardware-backed)' : ''}
          </span>
        </div>
        {vault.keystore?.note ? (
          <Notice tone="warning">{vault.keystore.note}</Notice>
        ) : null}
        <p className="small secondary mt-2">
          MyBot never shows a stored secret, and no part of the reasoning layer
          can reach one. Credentials are used by performing an operation on your
          behalf, not by handing the value to anything that asks.
        </p>
      </div>

      <div className="section-label">Your data</div>
      <div className="card">
        <div className="row-between">
          <div>
            <div className="card-title">Export everything</div>
            <p className="small secondary mt-1">
              Plain JSON. Your Life Graph, memories, obligations, documents and
              the full audit history.
            </p>
          </div>
          <button
            className="btn"
            onClick={async () => {
              const data = await api.get<unknown>('/api/v1/account/export');
              const blob = new Blob([JSON.stringify(data, null, 2)], {
                type: 'application/json',
              });
              const url = URL.createObjectURL(blob);
              const link = document.createElement('a');
              link.href = url;
              link.download = `mybot-export-${new Date().toISOString().slice(0, 10)}.json`;
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export
          </button>
        </div>
      </div>
    </>
  );
}
