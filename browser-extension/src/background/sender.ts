// Who sent a runtime message. Content scripts run inside the chat site's
// renderer process, which the browser treats as untrusted: a compromised
// renderer can send any message a content script could. So control messages
// (settings, flush, status) are taken only from the extension's own pages, and
// relay messages only from a content script in a tab. Pure, for unit tests.

/** The fields of runtime.MessageSender this module reads. */
export interface SenderLike {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number };
}

/**
 * True when the message came from one of this extension's own pages (popup,
 * options, whether or not it is open in a tab): same extension id, and a sender
 * URL on the extension's own scheme and host. `extensionBaseUrl` is
 * runtime.getURL(''). Scheme and host are compared rather than `URL.origin`,
 * which some engines report as "null" for extension schemes.
 */
export function isExtensionPage(sender: SenderLike, runtimeId: string, extensionBaseUrl: string): boolean {
  if (!runtimeId || sender.id !== runtimeId || typeof sender.url !== 'string') return false;
  try {
    const from = new URL(sender.url);
    const own = new URL(extensionBaseUrl);
    return own.host !== '' && from.protocol === own.protocol && from.host === own.host;
  } catch {
    return false;
  }
}

/** True when the message came from this extension's content script in a tab. */
export function isOwnContentScript(sender: SenderLike, runtimeId: string): boolean {
  return !!runtimeId && sender.id === runtimeId && typeof sender.tab?.id === 'number';
}

/** The host of the frame that sent a relay message, from the browser's own
 *  record of the sender rather than from the message body. */
export function senderHost(sender: SenderLike): string | null {
  if (typeof sender.url !== 'string') return null;
  try {
    return new URL(sender.url).host || null;
  } catch {
    return null;
  }
}
