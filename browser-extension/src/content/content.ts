// ISOLATED-world content script. The bridge between the page (MAIN interceptor)
// and the extension service worker. Deliberately thin: take events only from
// the private port the interceptor handed over at document_start
// (src/shared/channel.ts), check their shape, and forward them to the SW. All
// parsing/normalizing happens in the SW so this script stays resistant to page
// interference.
//
// This script never listens to window messages: any page script can post one.

import type { RelayMessage } from '../shared/types.js';
import { ext } from '../shared/browser.js';
import { acceptChannel, type ChannelHost } from '../shared/channel.js';
import { parseInterceptEvent } from '../shared/validate.js';

/**
 * True only when the extension context this content script belongs to is still
 * alive. After the extension is reloaded/updated, previously-injected content
 * scripts in already-open tabs are orphaned: `runtime` is torn down and
 * touching `.sendMessage` throws. Guarding here degrades gracefully (a tab
 * refresh re-injects a fresh, connected content script).
 */
function extensionAlive(): boolean {
  try {
    return ext != null && !!ext.runtime && !!ext.runtime.id;
  } catch {
    return false;
  }
}

let warnedInvalidated = false;

function relay(raw: unknown): void {
  // The interceptor sends JSON strings; anything else did not come from it.
  if (typeof raw !== 'string') return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  const event = parseInterceptEvent(parsed);
  if (!event) return;

  if (!extensionAlive()) {
    if (!warnedInvalidated) {
      warnedInvalidated = true;
      console.debug('[agent-beacon] extension context invalidated; refresh this tab to resume capture.');
    }
    return;
  }

  const message: RelayMessage = {
    type: 'BEACON_RAW',
    host: window.location.host,
    event,
  };
  // Fire-and-forget; the SW may be asleep and will wake to handle it. Wrap in
  // try/catch in case the context is invalidated between the check and the call.
  try {
    void ext.runtime.sendMessage(message).catch(() => {
      /* SW not ready / extension reloading — safe to drop a single event */
    });
  } catch {
    /* context invalidated mid-flight */
  }
}

acceptChannel(window as unknown as ChannelHost, (port) => {
  port.onmessage = (event: MessageEvent) => relay(event.data);
});
