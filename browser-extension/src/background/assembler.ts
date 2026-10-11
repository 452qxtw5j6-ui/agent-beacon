// Accumulates raw intercept events into completed ChatTurns, one parser per
// (tabId, reqId). No chrome.* — unit-testable. State is intentionally in-memory:
// a stream lasts seconds and the SW is kept awake while one is active; the
// DURABLE state (the delivery queue) lives in storage, not here.
//
// The state is bounded. A tab holds at most `maxPerTab` open streams and the
// worker at most `maxTotal`; a stream with no event for `maxIdleMs`, or one
// that has buffered more than `maxEntryBytes`, is closed. Closing a stream that
// never saw `done` finalizes it the same way an aborted stream is: whatever was
// parsed becomes a best-effort partial turn (no completedAt), or nothing if the
// parser captured nothing. So a stream that never ends cannot hold memory, or
// the keepalive, forever.

import type { ChatTurn } from '../shared/types.js';
import type { InterceptEvent } from '../shared/types.js';
import { adapterForHost, type SiteAdapter, type TurnParser } from '../adapters/adapter.js';

interface Entry {
  tabId: number;
  adapter: SiteAdapter;
  parser: TurnParser;
  /** Last event time (epoch ms). */
  seenAt: number;
  /** Request body plus chunk characters buffered so far. */
  bytes: number;
}

export interface AssemblerLimits {
  maxPerTab: number;
  maxTotal: number;
  maxIdleMs: number;
  maxEntryBytes: number;
}

export const DEFAULT_LIMITS: Readonly<AssemblerLimits> = Object.freeze({
  maxPerTab: 8,
  maxTotal: 64,
  // Long reasoning turns can go quiet for a while between chunks.
  maxIdleMs: 10 * 60_000,
  maxEntryBytes: 32 * 1024 * 1024,
});

export class Assembler {
  // Map iteration order is insertion order, which makes the first entry for a
  // tab its oldest.
  private entries = new Map<string, Entry>();
  private readonly limits: AssemblerLimits;
  private readonly now: () => number;

  constructor(limits: Partial<AssemblerLimits> = {}, now: () => number = Date.now) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.now = now;
  }

  private key(tabId: number, reqId: string): string {
    return `${tabId}:${reqId}`;
  }

  /**
   * Feed one intercept event. Returns the turns finalized by it: the stream's
   * own turn on 'done'/'error', plus any older stream closed to make room.
   */
  handle(host: string, tabId: number | undefined, event: InterceptEvent): ChatTurn[] {
    const tab = tabId ?? -1;
    const k = this.key(tab, event.reqId);
    const out: ChatTurn[] = [];

    if (event.kind === 'request') {
      // A repeated request id replaces nothing: ids are random, so a repeat is
      // not the interceptor's.
      if (this.entries.has(k)) return out;
      const adapter = adapterForHost(host);
      if (!adapter || !adapter.matchesRequest(event.url, event.method)) return out;
      this.makeRoom(tab, out);
      const parser = adapter.createParser(event.reqId);
      parser.onRequest(event.url, event.method, event.body);
      this.entries.set(k, {
        tabId: tab,
        adapter,
        parser,
        seenAt: this.now(),
        bytes: event.body?.length ?? 0,
      });
      return out;
    }

    const entry = this.entries.get(k);
    if (!entry) return out;
    entry.seenAt = this.now();

    switch (event.kind) {
      case 'chunk':
        entry.bytes += event.chunk.length;
        if (entry.bytes > this.limits.maxEntryBytes) {
          this.close(k, out);
          return out;
        }
        entry.parser.onChunk(event.chunk);
        return out;
      case 'done':
      case 'error':
        this.close(k, out);
        return out;
    }
    return out;
  }

  /** Close every stream idle for longer than maxIdleMs. */
  sweep(): ChatTurn[] {
    const out: ChatTurn[] = [];
    const cutoff = this.now() - this.limits.maxIdleMs;
    for (const [k, e] of [...this.entries]) {
      if (e.seenAt <= cutoff) this.close(k, out);
    }
    return out;
  }

  /** Close every stream of a tab (the tab was closed or navigated away). */
  closeTab(tabId: number): ChatTurn[] {
    const out: ChatTurn[] = [];
    for (const [k, e] of [...this.entries]) {
      if (e.tabId === tabId) this.close(k, out);
    }
    return out;
  }

  /** Number of in-flight streams (used to decide SW keepalive). */
  get active(): number {
    return this.entries.size;
  }

  private makeRoom(tabId: number, out: ChatTurn[]): void {
    const forTab = [...this.entries].filter(([, e]) => e.tabId === tabId);
    for (let i = 0; i <= forTab.length - this.limits.maxPerTab; i++) this.close(forTab[i][0], out);
    while (this.entries.size >= this.limits.maxTotal) {
      const oldest = this.entries.keys().next().value as string;
      this.close(oldest, out);
    }
  }

  private close(k: string, out: ChatTurn[]): void {
    const entry = this.entries.get(k);
    if (!entry) return;
    this.entries.delete(k);
    entry.parser.onDone();
    const turn = entry.parser.getTurn();
    if (turn) out.push(turn);
  }
}
