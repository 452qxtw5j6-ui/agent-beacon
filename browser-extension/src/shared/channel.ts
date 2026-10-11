// Private channel between the MAIN-world interceptor and the ISOLATED-world
// content script.
//
// The two scripts share the page's window but not its JavaScript world. The old
// bridge was window.postMessage, which every page script can call, so any script
// on claude.ai or chatgpt.com could forge telemetry. Now the interceptor creates
// a MessageChannel and hands one end to the content script once, at
// document_start, before any page script exists. Afterwards events travel only
// over that port, which lives in two closures and is never reachable from the
// page. The content script no longer listens to window messages at all.
//
// The hand-over is a synchronously dispatched event, never window.postMessage:
// postMessage delivers in a later task, and a page script that ran in between
// could register a listener and read the port from `event.ports`. Dispatch is
// synchronous, so the port is delivered and claimed before the dispatch
// returns, while nothing but the two extension scripts has run.
//
// Chrome injects document_start scripts in manifest order, but neither side
// relies on it. Whichever script runs second completes the hand-over:
//  - The interceptor dispatches PORT_EVENT (cancelable) carrying the port. If
//    the content script is already listening it claims the port and cancels the
//    event, which tells the interceptor the port arrived.
//  - Otherwise the interceptor waits for HELLO_EVENT, which the content script
//    dispatches when it starts, and answers it by dispatching PORT_EVENT again.
// Both sides accept exactly one hand-over and stop listening when the document
// finishes loading.
//
// Residual risk, stated plainly: a script in the page's own world can still
// change what the page fetches, or replace window.fetch after the interceptor,
// because the page is the data source. What it can no longer do is inject or
// alter events on the channel without holding the port. If the interceptor
// failed to run at all, a page script could hand the content script a port of
// its own while the document is still loading; nothing else can.

/** Fired by the interceptor (a MessageEvent whose ports[0] is the channel). */
export const PORT_EVENT = '__beacon_port__';
/** Fired by the content script to ask an already-installed interceptor for the port. */
export const HELLO_EVENT = '__beacon_hello__';

/** The DOM surface both halves need: the page's window in production, a plain
 *  EventTarget in unit tests. */
export interface ChannelHost extends EventTarget {
  document?: { readyState?: string; addEventListener?(type: string, fn: () => void, opts?: unknown): void };
}

/** True while the hand-over window is open: before the document finishes
 *  parsing. A host without a document (unit tests) is always open. */
function loading(host: ChannelHost): boolean {
  const state = host.document?.readyState;
  return state == null || state === 'loading';
}

/** Run `fn` once, when the document finishes parsing. */
function onLoaded(host: ChannelHost, fn: () => void): void {
  host.document?.addEventListener?.('DOMContentLoaded', fn, { once: true });
}

/**
 * MAIN-world half. Creates the channel, starts the hand-over and returns the
 * end the interceptor keeps. Call once, at document_start.
 */
export function offerChannel(
  host: ChannelHost,
  makeChannel: () => MessageChannel = () => new MessageChannel(),
): MessagePort {
  const { port1, port2 } = makeChannel();
  let handed = false;

  const offer = (): void => {
    if (handed) return;
    const event = new MessageEvent(PORT_EVENT, { ports: [port2], cancelable: true });
    // dispatchEvent returns false when a listener called preventDefault, which
    // the content script does when it claims the port.
    if (!host.dispatchEvent(event)) {
      handed = true;
      host.removeEventListener(HELLO_EVENT, offer);
    }
  };

  host.addEventListener(HELLO_EVENT, offer);
  onLoaded(host, () => host.removeEventListener(HELLO_EVENT, offer));
  offer();
  return port1;
}

/**
 * ISOLATED-world half. Claims the first port offered while the document is
 * still loading and passes it to `onPort`. Call once, at document_start.
 */
export function acceptChannel(host: ChannelHost, onPort: (port: MessagePort) => void): void {
  let claimed = false;

  const claim = (event: Event): void => {
    if (claimed || !loading(host)) return;
    const port = (event as MessageEvent).ports?.[0];
    if (!port) return;
    claimed = true;
    event.preventDefault();
    event.stopImmediatePropagation();
    host.removeEventListener(PORT_EVENT, claim);
    onPort(port);
  };

  host.addEventListener(PORT_EVENT, claim);
  onLoaded(host, () => host.removeEventListener(PORT_EVENT, claim));
  // An interceptor that ran first answers this synchronously.
  host.dispatchEvent(new Event(HELLO_EVENT));
}
