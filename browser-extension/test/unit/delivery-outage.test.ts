// Collector outages against the durable delivery queue (#863). A fake
// extension environment stands in for the browser: storage.local persists
// across simulated service-worker restarts, alarms follow Chrome's ~30s clamp,
// and a fake loopback collector records every POST it sees. Time is driven by
// fake timers, so a ten-minute or day-long outage runs instantly.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatTurn, Settings } from '../../src/shared/types.js';
import { DEFAULT_SETTINGS } from '../../src/shared/types.js';

const MINUTE = 60_000;
const ALARM_CLAMP_MS = 30_000;
const ENDPOINT = DEFAULT_SETTINGS.endpoint;

type Alarm = { name: string };
type Listener = (alarm: Alarm) => void;
const env = vi.hoisted(() => ({
  storage: new Map<string, unknown>(),
  alarms: new Map<string, number>(),
  listeners: [] as Listener[],
}));

vi.mock('../../src/shared/browser.js', () => ({
  ext: {
    storage: {
      local: {
        // Clone both ways, as the real storage serializes values.
        get: async (key: string) =>
          env.storage.has(key) ? { [key]: structuredClone(env.storage.get(key)) } : {},
        set: async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) env.storage.set(k, structuredClone(v));
        },
      },
    },
    alarms: {
      // Chrome delays an alarm due sooner than ~30s from now to ~30s from now.
      create: (name: string, info: { when: number }) => {
        env.alarms.set(name, Math.max(info.when, Date.now() + ALARM_CLAMP_MS));
      },
      onAlarm: { addListener: (fn: Listener) => env.listeners.push(fn) },
    },
  },
}));

type Delivery = typeof import('../../src/background/delivery.js');
type StoredItem = {
  id: string; endpoint: string; envelope: unknown; attempts: number;
  nextAttemptAt?: number; queuedAt?: number; bytes?: number;
};

/** A fake loopback collector: records every POST, accepts only while `up`. */
const collector = {
  up: true,
  attempted: [] as string[],
  received: [] as string[],
  byEndpoint: new Map<string, boolean>(),
};

function promptId(body: unknown): string | undefined {
  if (Array.isArray(body)) {
    for (const v of body) {
      const found = promptId(v);
      if (found) return found;
    }
  } else if (body && typeof body === 'object') {
    const o = body as Record<string, unknown>;
    if (o.key === 'beacon.prompt.id') return (o.value as { stringValue: string }).stringValue;
    for (const v of Object.values(o)) {
      const found = promptId(v);
      if (found) return found;
    }
  }
  return undefined;
}

async function fakeFetch(url: string, init: { body: string }): Promise<{ ok: boolean }> {
  const id = promptId(JSON.parse(init.body)) ?? '?';
  collector.attempted.push(id);
  const up = collector.byEndpoint.get(url) ?? collector.up;
  if (!up) throw new TypeError('Failed to fetch'); // connection refused
  collector.received.push(id);
  return { ok: true };
}

let delivery: Delivery;

/** Start (or restart) the service worker: fresh module state, persisted storage. */
async function startWorker(): Promise<void> {
  vi.resetModules();
  env.listeners.length = 0;
  delivery = await import('../../src/background/delivery.js');
  delivery.installFlushAlarm();
  await settle();
}

/** Let fire-and-forget flushes finish. The fakes never wait on a macrotask. */
async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
}

/** Advance the clock by `ms`, firing every alarm that comes due on the way. */
async function runFor(ms: number): Promise<number> {
  const end = Date.now() + ms;
  let fired = 0;
  for (;;) {
    const due = [...env.alarms.entries()].filter(([, t]) => t <= end).sort((a, b) => a[1] - b[1])[0];
    if (!due) break;
    vi.setSystemTime(Math.max(due[1], Date.now()));
    env.alarms.delete(due[0]);
    for (const fn of env.listeners) fn({ name: due[0] });
    fired += 1;
    await settle();
  }
  vi.setSystemTime(end);
  return fired;
}

function turn(id: string, promptText = `prompt ${id}`): ChatTurn {
  return {
    site: 'claude_web',
    sessionId: 'conv-1',
    turnId: id,
    promptText,
    inputMessages: [{ role: 'user', text: `prompt ${id}` }],
    outputMessages: [{ role: 'assistant', text: `answer ${id}` }],
    responseText: `answer ${id}`,
    toolCalls: [],
    startedAt: Date.now(),
    completedAt: Date.now(),
    captureMode: 'sse',
  };
}

const settings: Settings = { ...DEFAULT_SETTINGS };

function queue(): StoredItem[] {
  return (env.storage.get('delivery_queue') as StoredItem[] | undefined) ?? [];
}

function stored(id: string, over: Partial<StoredItem> = {}): StoredItem {
  return { id, endpoint: ENDPOINT, envelope: { id }, attempts: 0, queuedAt: Date.now(), ...over };
}

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(1_000_000);
  env.storage.clear();
  env.alarms.clear();
  collector.up = true;
  collector.attempted = [];
  collector.received = [];
  collector.byEndpoint.clear();
  vi.stubGlobal('fetch', vi.fn(fakeFetch));
  await startWorker();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('collector outage', () => {
  it('delivers every turn captured during a ten-minute outage once it recovers', async () => {
    collector.up = false;
    const ids = Array.from({ length: 8 }, (_, i) => `t${i}`);
    for (const id of ids) {
      await delivery.enqueueTurn(turn(id), settings);
      await runFor(75_000); // 8 x 75s = 10 minutes down
    }
    expect(queue().map((i) => i.id)).toEqual(ids);
    expect(collector.received).toEqual([]);

    collector.up = true;
    await runFor(delivery.MAX_RETRY_DELAY_MS);

    expect(collector.received).toEqual(ids); // all of them, in capture order
    expect(queue()).toEqual([]);
  });

  it('keeps retrying through an outage of many hours, well past the old six attempts', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('long'), settings);
    const fired = await runFor(6 * 60 * MINUTE);
    expect(fired).toBeGreaterThan(300);
    expect(queue()).toEqual([expect.objectContaining({ id: 'long' })]);
    expect(queue()[0].attempts).toBeGreaterThan(300);

    collector.up = true;
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['long']);
  });

  it('probes a down collector with the oldest batch only, not every queued batch', async () => {
    collector.up = false;
    for (const id of ['a', 'b', 'c', 'd']) {
      await delivery.enqueueTurn(turn(id), settings);
      await runFor(MINUTE);
    }
    await runFor(10 * MINUTE);
    expect(new Set(collector.attempted)).toEqual(new Set(['a']));
  });

  it('sends nothing twice: each turn reaches the collector exactly once', async () => {
    collector.up = false;
    const ids = ['x1', 'x2', 'x3', 'x4', 'x5'];
    for (const id of ids) await delivery.enqueueTurn(turn(id), settings);
    await runFor(4 * MINUTE);
    collector.up = true;
    // The backlog is due: the alarm, a popup "flush now" and a new turn all
    // race the same queue.
    vi.setSystemTime(queue()[0].nextAttemptAt!);
    env.alarms.clear();
    await Promise.all([
      ...env.listeners.map(async (fn) => fn({ name: 'beacon_flush' })),
      delivery.flush(),
      delivery.flush(),
      delivery.enqueueTurn(turn('x6'), settings),
    ]);
    await settle();
    expect(collector.received).toEqual([...ids, 'x6']);
    await runFor(10 * MINUTE);
    expect(collector.received).toEqual([...ids, 'x6']);
    expect(queue()).toEqual([]);
  });

  it('holds new turns behind the waiting backlog so a recovery delivers in order', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('old'), settings);
    await runFor(5 * MINUTE);
    collector.up = true;
    // The collector is back, but the backlog's retry is not due yet. A new turn
    // must not jump ahead of it.
    await delivery.enqueueTurn(turn('new'), settings);
    expect(collector.received).toEqual([]);
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['old', 'new']);
  });

  it('keeps the undelivered tail in order when the collector drops mid-drain', async () => {
    collector.up = false;
    const ids = ['m1', 'm2', 'm3', 'm4'];
    for (const id of ids) await delivery.enqueueTurn(turn(id), settings);
    await runFor(2 * MINUTE);

    collector.up = true;
    let died = false;
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { body: string }) => {
      if (!died && collector.received.length === 2) {
        died = true; // the collector dies after accepting two batches
        collector.up = false;
      }
      return fakeFetch(url, init);
    }));
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['m1', 'm2']);
    expect(queue().map((i) => i.id)).toEqual(['m3', 'm4']);

    collector.up = true;
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(ids);
  });

  it('does not let one unreachable endpoint hold back batches for another', async () => {
    const other = 'http://localhost:4318/v1/logs';
    collector.byEndpoint.set(ENDPOINT, false);
    await delivery.enqueueTurn(turn('down'), settings);
    await delivery.enqueueTurn(turn('up'), { ...settings, endpoint: other });
    expect(collector.received).toEqual(['up']);
    expect(queue().map((i) => i.id)).toEqual(['down']);
  });
});

describe('service-worker restarts', () => {
  it('survives the worker being suspended and restarted mid-outage', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('s1'), settings);
    await runFor(2 * MINUTE);
    await delivery.enqueueTurn(turn('s2'), settings);
    await startWorker(); // suspended: in-memory state is gone, storage and alarms are not
    await runFor(3 * MINUTE);
    collector.up = true;
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['s1', 's2']);
  });

  it('resumes delivery on worker start when a restart or update cleared the alarm', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('r1'), settings);
    await delivery.enqueueTurn(turn('r2'), settings);
    await runFor(5 * MINUTE);
    env.alarms.clear(); // browser restart / extension update
    collector.up = true;
    await runFor(10 * MINUTE);
    expect(collector.received).toEqual([]); // nothing would ever retry...

    await startWorker(); // ...until the worker starts again, with no new turn
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['r1', 'r2']);
    expect(queue()).toEqual([]);
  });

  it('does not touch storage on worker start when nothing is queued', async () => {
    expect(env.storage.has('delivery_queue')).toBe(false);
    expect(env.alarms.size).toBe(0);
  });
});

describe('queue bounds', () => {
  it('expires batches older than the age limit and keeps younger ones', async () => {
    const now = Date.now();
    env.storage.set('delivery_queue', [
      stored('expired', { queuedAt: now - delivery.MAX_QUEUE_AGE_MS }),
      stored('young', { queuedAt: now - delivery.MAX_QUEUE_AGE_MS + MINUTE }),
    ]);
    const sentAt: number[] = [];
    vi.stubGlobal('fetch', vi.fn(async () => {
      sentAt.push(Date.now());
      throw new TypeError('Failed to fetch');
    }));
    await delivery.flush();
    expect(queue().map((i) => i.id)).toEqual(['young']);
    expect(sentAt).toEqual([now]); // only the young batch was tried

    await runFor(2 * MINUTE);
    expect(queue()).toEqual([]); // past its limit now
    const expiresAt = now + MINUTE;
    expect(sentAt.length).toBeGreaterThan(1);
    expect(sentAt.every((t) => t < expiresAt)).toBe(true); // never sent once expired
  });

  it('drops a batch captured at the start of an outage that outlasts the age limit', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('first'), settings);
    await runFor(delivery.MAX_QUEUE_AGE_MS - MINUTE);
    await delivery.enqueueTurn(turn('late'), settings);
    await runFor(2 * MINUTE);
    collector.up = true;
    await runFor(delivery.MAX_RETRY_DELAY_MS);
    expect(collector.received).toEqual(['late']);
  });

  it('gives a batch queued by an older build a full age window', async () => {
    const legacy = stored('legacy', { attempts: 3 });
    delete legacy.queuedAt;
    env.storage.set('delivery_queue', [legacy]);
    collector.up = false;
    await delivery.flush();
    expect(queue()).toEqual([expect.objectContaining({ id: 'legacy', queuedAt: Date.now() })]);
  });

  it('caps the batch count, dropping the oldest first and keeping order', async () => {
    const backlog = Array.from({ length: delivery.MAX_QUEUE_ITEMS }, (_, i) =>
      stored(`q${i}`, { nextAttemptAt: Date.now() + MINUTE }));
    env.storage.set('delivery_queue', backlog);
    collector.up = false;
    for (const id of ['n1', 'n2', 'n3']) await delivery.enqueueTurn(turn(id), settings);

    const ids = queue().map((i) => i.id);
    expect(ids).toHaveLength(delivery.MAX_QUEUE_ITEMS);
    expect(ids.slice(0, 2)).toEqual(['q3', 'q4']);
    expect(ids.slice(-3)).toEqual(['n1', 'n2', 'n3']);
  });

  it('caps the queued bytes, dropping the oldest first', async () => {
    // Each envelope serializes to {"pad":"x...x"}: the pad plus 10 bytes. Four
    // of them come to 4000 bytes under the cap.
    const each = delivery.MAX_QUEUE_BYTES / 4 - 1000;
    const big = (id: string) => stored(id, { envelope: { pad: 'x'.repeat(each - 10) } });
    env.storage.set('delivery_queue', ['b0', 'b1', 'b2', 'b3'].map(big));
    collector.up = false;
    await delivery.flush();
    expect(queue().map((i) => i.bytes)).toEqual([each, each, each, each]);

    // A turn over 4000 bytes tips the queue over: the oldest batch goes.
    await delivery.enqueueTurn(turn('newest', 'p'.repeat(10_000)), settings);
    const q = queue();
    expect(q.map((i) => i.id)).toEqual(['b1', 'b2', 'b3', 'newest']);
    expect(q.reduce((sum, i) => sum + i.bytes!, 0)).toBeLessThanOrEqual(delivery.MAX_QUEUE_BYTES);
  });

  it('keeps a lone batch over the byte cap until a newer one replaces it', async () => {
    env.storage.set('delivery_queue', [
      stored('huge', { envelope: { pad: 'x'.repeat(delivery.MAX_QUEUE_BYTES) } }),
    ]);
    collector.up = false;
    await delivery.flush();
    expect(queue().map((i) => i.id)).toEqual(['huge']);
    await delivery.enqueueTurn(turn('after'), settings);
    expect(queue().map((i) => i.id)).toEqual(['after']);
  });
});

describe('retry backoff', () => {
  it('doubles from half a second and caps at a minute', () => {
    const delays = Array.from({ length: 12 }, (_, i) => delivery.retryDelay(i + 1));
    expect(delays).toEqual([500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000,
      60_000, 60_000, 60_000, 60_000, 60_000]);
    expect(delivery.retryDelay(10_000)).toBe(60_000);
  });

  it('stores the deadline of each failure and wakes at it, clamped by the alarm floor', async () => {
    collector.up = false;
    await delivery.enqueueTurn(turn('b'), settings);
    const seen: Array<{ attempts: number; wait: number }> = [];
    for (let i = 0; i < 9; i++) {
      const [item] = queue();
      seen.push({ attempts: item.attempts, wait: item.nextAttemptAt! - Date.now() });
      expect(env.alarms.get('beacon_flush')).toBe(
        Math.max(item.nextAttemptAt!, Date.now() + ALARM_CLAMP_MS));
      await runFor(env.alarms.get('beacon_flush')! - Date.now());
    }
    expect(seen.map((s) => s.attempts)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(seen.map((s) => s.wait)).toEqual([500, 1_000, 2_000, 4_000, 8_000, 16_000,
      32_000, 60_000, 60_000]);
    expect(collector.attempted).toEqual(Array(10).fill('b'));
  });
});
