// Bounded turn assembly (src/background/assembler.ts): per-tab and total caps,
// idle expiry, per-stream byte cap and tab cleanup all finalize or drop open
// streams, so nothing stays in memory (or keeps the worker awake) forever.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../../src/adapters/claude.js';
import { Assembler } from '../../src/background/assembler.js';
import type { InterceptEvent } from '../../src/shared/types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SSE = readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'claude', 'simple-turn.sse'), 'utf8');
const CONV = '11111111-2222-3333-4444-555555555555';
const URL = `/api/organizations/org-x/chat_conversations/${CONV}/completion`;
const HOST = 'claude.ai';

const id = (n: number) => `req-${String(n).padStart(8, '0')}`;
const request = (reqId: string): InterceptEvent => ({
  kind: 'request',
  reqId,
  url: URL,
  method: 'POST',
  body: JSON.stringify({ prompt: 'hi', conversation_id: CONV }),
});

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe('Assembler', () => {
  it('assembles a full turn and forgets it on done', () => {
    const a = new Assembler();
    a.handle(HOST, 1, request(id(1)));
    expect(a.active).toBe(1);
    a.handle(HOST, 1, { kind: 'chunk', reqId: id(1), chunk: SSE });
    const turns = a.handle(HOST, 1, { kind: 'done', reqId: id(1) });
    expect(turns).toHaveLength(1);
    expect(turns[0].responseText).toBe('Paris.');
    expect(a.active).toBe(0);
  });

  it('ignores events for a request id it never registered', () => {
    const a = new Assembler();
    expect(a.handle(HOST, 1, { kind: 'done', reqId: id(9) })).toEqual([]);
    expect(a.handle(HOST, 1, { kind: 'chunk', reqId: id(9), chunk: SSE })).toEqual([]);
    expect(a.active).toBe(0);
  });

  it('does not let another tab address a stream', () => {
    const a = new Assembler();
    a.handle(HOST, 1, request(id(1)));
    expect(a.handle(HOST, 2, { kind: 'done', reqId: id(1) })).toEqual([]);
    expect(a.active).toBe(1);
  });

  it('does not let a repeated request id replace an open stream', () => {
    const a = new Assembler();
    a.handle(HOST, 1, request(id(1)));
    a.handle(HOST, 1, { kind: 'chunk', reqId: id(1), chunk: SSE });
    a.handle(HOST, 1, request(id(1)));
    const [turn] = a.handle(HOST, 1, { kind: 'done', reqId: id(1) });
    expect(turn.responseText).toBe('Paris.');
  });

  it('ignores requests for a host with no adapter', () => {
    const a = new Assembler();
    a.handle('example.com', 1, request(id(1)));
    expect(a.active).toBe(0);
  });

  it('caps open streams per tab, closing the oldest', () => {
    const a = new Assembler({ maxPerTab: 3 });
    for (let i = 1; i <= 5; i++) a.handle(HOST, 1, request(id(i)));
    expect(a.active).toBe(3);
    // The two oldest were closed; the newest three are still addressable.
    expect(a.handle(HOST, 1, { kind: 'done', reqId: id(1) })).toEqual([]);
    expect(a.handle(HOST, 1, { kind: 'done', reqId: id(5) })).toHaveLength(1);
    // Another tab is unaffected by tab 1's cap.
    a.handle(HOST, 2, request(id(1)));
    expect(a.active).toBe(3);
  });

  it('caps open streams in total', () => {
    const a = new Assembler({ maxPerTab: 100, maxTotal: 4 });
    for (let tab = 1; tab <= 10; tab++) a.handle(HOST, tab, request(id(tab)));
    expect(a.active).toBe(4);
  });

  it('finalizes a stream that went idle as a partial turn', () => {
    const c = clock();
    const a = new Assembler({ maxIdleMs: 60_000 }, c.now);
    a.handle(HOST, 1, request(id(1)));
    a.handle(HOST, 1, { kind: 'chunk', reqId: id(1), chunk: SSE.slice(0, SSE.length / 2) });
    c.advance(30_000);
    expect(a.sweep()).toEqual([]);
    c.advance(30_001);
    const turns = a.sweep();
    expect(a.active).toBe(0);
    expect(turns).toHaveLength(1);
    expect(turns[0].sessionId).toBe(CONV);
  });

  it('keeps a stream alive while events keep arriving', () => {
    const c = clock();
    const a = new Assembler({ maxIdleMs: 60_000 }, c.now);
    a.handle(HOST, 1, request(id(1)));
    for (let i = 0; i < 5; i++) {
      c.advance(50_000);
      a.handle(HOST, 1, { kind: 'chunk', reqId: id(1), chunk: '' });
      a.sweep();
    }
    expect(a.active).toBe(1);
  });

  it('closes a stream that buffers more than its byte cap', () => {
    const a = new Assembler({ maxEntryBytes: 1024 });
    a.handle(HOST, 1, request(id(1)));
    a.handle(HOST, 1, { kind: 'chunk', reqId: id(1), chunk: 'x'.repeat(2048) });
    expect(a.active).toBe(0);
  });

  it('closes every stream of a removed tab', () => {
    const a = new Assembler();
    a.handle(HOST, 1, request(id(1)));
    a.handle(HOST, 1, request(id(2)));
    a.handle(HOST, 2, request(id(3)));
    a.closeTab(1);
    expect(a.active).toBe(1);
  });
});
