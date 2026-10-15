// The one source of the serializer every Beacon runtime plugin runs on its hook payloads.
//
// Each plugin installs as a single self-contained file that its runtime loads directly, so a plugin
// cannot import this module at run time. Instead the region between the two markers below is
// written into each plugin by `bun run sync` (sync-safe-clone.ts), verbatim into the TypeScript
// plugins and with its two type annotations removed into OpenClaw's JavaScript one. `bun run check`
// in every plugin, and `bun test` here, fail when any copy differs from this file.
//
// Edit the region here, never in a plugin, then run `bun run sync` in this directory.

// BEGIN shared/safe-clone
// Generated from plugins/shared/safe-clone.ts by `bun run sync`. Edit that file, not this block:
// `bun run check` fails when the two differ.

// How deep into a payload the serializer will walk before giving up.
const maxDepth = 8

// safeClone turns a live runtime payload into something JSON.stringify accepts.
//
// Runtimes hand plugins live objects, not plain data: AbortSignals, SDK class instances, parent
// references, provider message objects, and tool inputs that are mutable by design. JSON.stringify
// throws on a circular reference and on a bigint, and silently flattens an Error to {}, so each is
// handled here rather than losing the whole payload to one bad field.
//
// Cycles are tracked along the current path and released on the way out, so an object that legibly
// appears twice -- the same file path referenced from two places in one edit -- is kept both times.
// A WeakSet that never released would drop the second occurrence as if it were a cycle.
function safeClone(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (value === null) return null
  const kind = typeof value
  if (kind === "function" || kind === "symbol" || kind === "undefined") return undefined
  if (kind === "bigint") return String(value)
  if (typeof value !== "object") return value
  if (depth >= maxDepth) return undefined

  if (seen.has(value)) return undefined
  if (value instanceof Error) return { name: value.name, message: value.message }
  // Match native JSON: an invalid Date is null, not a lost event.
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : null

  seen.add(value)
  try {
    if (Array.isArray(value)) {
      return value.map((item) => safeClone(item, depth + 1, seen))
    }
    const out: Record<string, unknown> = {}
    for (const [key, nested] of Object.entries(value)) {
      const cloned = safeClone(nested, depth + 1, seen)
      if (cloned !== undefined) out[key] = cloned
    }
    return out
  } finally {
    seen.delete(value)
  }
}
// END shared/safe-clone

export { maxDepth, safeClone }
