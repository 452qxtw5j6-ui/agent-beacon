// Runtime-message sender checks (src/background/sender.ts). Control messages
// come only from the extension's own pages; content scripts run in the chat
// site's renderer and must not be able to change settings or trigger a flush.
import { describe, it, expect } from 'vitest';
import { isExtensionPage, isOwnContentScript, senderHost } from '../../src/background/sender.js';

const ID = 'abcdefghijklmnopabcdefghijklmnop';
const BASE = `chrome-extension://${ID}/`;

describe('isExtensionPage', () => {
  it('accepts the popup (no tab)', () => {
    expect(isExtensionPage({ id: ID, url: `${BASE}popup.html` }, ID, BASE)).toBe(true);
  });

  it('accepts the options page open in a tab', () => {
    expect(isExtensionPage({ id: ID, url: `${BASE}options.html`, tab: { id: 7 } }, ID, BASE)).toBe(true);
  });

  it('accepts a Firefox moz-extension page', () => {
    const base = 'moz-extension://0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0/';
    expect(isExtensionPage({ id: ID, url: `${base}options.html` }, ID, base)).toBe(true);
  });

  it.each([
    ['a content script on claude.ai', { id: ID, url: 'https://claude.ai/chat/x', tab: { id: 3 } }],
    ['a content script with no url', { id: ID, tab: { id: 3 } }],
    ['another extension', { id: 'zzzz', url: `${BASE}popup.html` }],
    ['another extension page origin', { id: ID, url: 'chrome-extension://otherotherotherotherotherother12/popup.html' }],
    ['no sender id', { url: `${BASE}popup.html` }],
    ['a malformed url', { id: ID, url: 'not a url' }],
  ])('refuses %s', (_name, sender) => {
    expect(isExtensionPage(sender, ID, BASE)).toBe(false);
  });

  it('refuses everything when the runtime id is unknown', () => {
    expect(isExtensionPage({ id: '', url: `${BASE}popup.html` }, '', BASE)).toBe(false);
  });
});

describe('isOwnContentScript', () => {
  it('accepts this extension in a tab', () => {
    expect(isOwnContentScript({ id: ID, url: 'https://claude.ai/', tab: { id: 3 } }, ID)).toBe(true);
  });
  it.each([
    ['no tab', { id: ID, url: 'https://claude.ai/' }],
    ['another extension', { id: 'other', tab: { id: 3 } }],
  ])('refuses %s', (_name, sender) => {
    expect(isOwnContentScript(sender, ID)).toBe(false);
  });
});

describe('senderHost', () => {
  it('reads the host from the browser-reported frame url', () => {
    expect(senderHost({ url: 'https://chatgpt.com/c/123' })).toBe('chatgpt.com');
  });
  it('returns null without a usable url', () => {
    expect(senderHost({})).toBeNull();
    expect(senderHost({ url: 'nope' })).toBeNull();
  });
});
