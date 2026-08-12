'use client';

/**
 * ASK — the chat surface.
 *
 * Secondary by design, and honest about its own grounding: every answer shows
 * whether it came from deterministic code or a model, and how many records it
 * cited. An answer with no citations about the user's life is a bug, and this
 * screen makes that visible rather than hiding it.
 */

import { useRef, useState } from 'react';

import { ApiError, api } from '@/lib/api';
import type { ChatAnswer } from '@/lib/api';
import { Badge, Notice, Spinner } from '@/components/ui';

const SUGGESTIONS = [
  'What do I need to worry about?',
  'What bills are coming up?',
  'When does my registration expire?',
  "What's happening this week?",
  'Remember that I prefer afternoon appointments',
  'Find the email from John about the contract',
];

interface Turn {
  role: 'user' | 'assistant';
  text: string;
  citations?: string[];
  groundedOnly?: boolean;
  model?: string | null;
  unavailable?: string[];
}

export default function AskPage() {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const conversation = useRef<string | null>(null);

  async function send(message: string) {
    const text = message.trim();
    if (!text || busy) return;
    setInput('');
    setError(null);
    setTurns((prev) => [...prev, { role: 'user', text }]);
    setBusy(true);
    try {
      const answer = await api.post<ChatAnswer>('/api/v1/chat', {
        message: text,
        conversation_id: conversation.current,
      });
      conversation.current = answer.conversation_id;
      setTurns((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: answer.text,
          citations: answer.citations,
          groundedOnly: answer.grounded_only,
          model: answer.model_used,
          unavailable: answer.unavailable,
        },
      ]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach MyBot.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>Ask MyBot</h1>
        <p className="page-subtitle">
          Answers come from your own records. If MyBot does not know something,
          it says so.
        </p>
      </header>

      {turns.length === 0 ? (
        <div className="suggestion-row">
          {SUGGESTIONS.map((suggestion) => (
            <button
              key={suggestion}
              className="suggestion"
              onClick={() => send(suggestion)}
            >
              {suggestion}
            </button>
          ))}
        </div>
      ) : null}

      <div className="chat-log">
        {turns.map((turn, index) => (
          <div key={index} style={{ display: 'flex', flexDirection: 'column' }}>
            <div
              className={`bubble ${turn.role === 'user' ? 'bubble-user' : 'bubble-bot'}`}
            >
              {turn.text}
            </div>
            {turn.role === 'assistant' ? (
              <div className="row wrap small muted mt-1" style={{ gap: 8 }}>
                {turn.groundedOnly ? (
                  <Badge tone="success">from your records</Badge>
                ) : (
                  <Badge tone="info">{turn.model ?? 'model'}</Badge>
                )}
                {turn.citations?.length ? (
                  <span>
                    {turn.citations.length} source
                    {turn.citations.length === 1 ? '' : 's'}
                  </span>
                ) : null}
                {turn.unavailable?.length ? (
                  <span style={{ color: 'var(--high)' }}>
                    could not check: {turn.unavailable.join(', ')}
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
        ))}
        {busy ? (
          <div className="bubble bubble-bot">
            <Spinner />
          </div>
        ) : null}
      </div>

      {error ? <Notice tone="critical">{error}</Notice> : null}

      <form
        className="composer"
        onSubmit={(event) => {
          event.preventDefault();
          void send(input);
        }}
      >
        <input
          className="input"
          value={input}
          placeholder="Ask about anything MyBot knows…"
          onChange={(event) => setInput(event.target.value)}
        />
        <button className="btn btn-primary" disabled={busy || !input.trim()}>
          Ask
        </button>
      </form>
    </>
  );
}
