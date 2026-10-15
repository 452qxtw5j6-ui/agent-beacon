// sync-safe-clone writes the shared serializer in safe-clone.ts into every plugin that runs it, and
// checks that each one still matches.
//
//   bun sync-safe-clone.ts                     write every plugin source and its embedded copy
//   bun sync-safe-clone.ts --check             fail if any plugin source or embedded copy differs
//   bun sync-safe-clone.ts src/beacon.ts       write one plugin source (a plugin's `bun run sync`)
//   bun sync-safe-clone.ts --check src/beacon.ts
//
// The plugins cannot import the serializer: each installs as one self-contained file its runtime
// loads directly. So the region between the markers in safe-clone.ts is the source, and each plugin
// carries a generated copy between the same markers. TypeScript plugins get the region verbatim.
// OpenClaw's plugin is JavaScript, so its copy has the region's type annotations removed by the
// exact line rewrites in jsRewrites below -- deliberately not a transpiler, whose output (comments
// dropped, statements reflowed) would change with the Bun version and make the check flaky.

import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join, relative, resolve } from "node:path"

export const beginMarker = "// BEGIN shared/safe-clone"
export const endMarker = "// END shared/safe-clone"

export const pluginsDir = resolve(import.meta.dir, "..")
export const repoRoot = resolve(pluginsDir, "..")
export const canonicalPath = join(import.meta.dir, "safe-clone.ts")
const assetsDir = join(repoRoot, "cli/beacon/internal/endpoint/hooks/assets")

// Every plugin that runs the shared serializer: its source and the copy embedded in the binary.
// OpenCode is deliberately absent: it never serializes a live payload with safeClone, and its
// structuredClone calls snapshot tool arguments for its own bookkeeping, where a depth limit or a
// flattened Error would lose state the plugin reads back later.
export const consumers = [
  { plugin: "cline-beacon", source: "src/beacon.ts", embedded: "cline/beacon.ts" },
  { plugin: "omo-beacon", source: "src/beacon.ts", embedded: "omo/beacon.ts" },
  { plugin: "omp-beacon", source: "src/beacon.ts", embedded: "omp/beacon.ts" },
  { plugin: "openclaw-beacon", source: "src/beacon.js", embedded: "openclaw/beacon.js" },
  { plugin: "pi-beacon", source: "src/beacon.ts", embedded: "pi/beacon.ts" },
  { plugin: "prime-beacon", source: "src/beacon.ts", embedded: "prime/beacon.ts" },
].map((entry) => ({
  ...entry,
  sourcePath: join(pluginsDir, entry.plugin, entry.source),
  embeddedPath: join(assetsDir, entry.embedded),
}))

// The only TypeScript in the region, and what it becomes in JavaScript. Each must match exactly one
// line, so an edit that adds a type annotation anywhere else, or changes one of these lines, fails
// the sync instead of writing TypeScript into a .js file.
export const jsRewrites: ReadonlyArray<readonly [string, string]> = [
  [
    "function safeClone(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {",
    "function safeClone(value, depth = 0, seen = new WeakSet()) {",
  ],
  ["    const out: Record<string, unknown> = {}", "    const out = {}"],
]

// extractBlock returns the region from the begin marker through the end marker, or throws when the
// markers are missing, repeated, or out of order.
export function extractBlock(source: string, label = "source"): string {
  const { start, end } = blockBounds(source, label)
  return source.slice(start, end)
}

function blockBounds(source: string, label: string): { start: number; end: number } {
  const start = source.indexOf(beginMarker)
  const endAt = source.indexOf(endMarker)
  if (start < 0 || endAt < 0) {
    throw new Error(`${label}: no "${beginMarker}" ... "${endMarker}" region`)
  }
  if (source.indexOf(beginMarker, start + 1) >= 0 || source.indexOf(endMarker, endAt + 1) >= 0) {
    throw new Error(`${label}: the shared/safe-clone markers appear more than once`)
  }
  if (endAt < start) throw new Error(`${label}: "${endMarker}" comes before "${beginMarker}"`)
  return { start, end: endAt + endMarker.length }
}

// toJavaScript applies jsRewrites to a TypeScript region.
export function toJavaScript(block: string): string {
  const lines = block.split("\n")
  for (const [ts, js] of jsRewrites) {
    const hits = lines.flatMap((line, index) => (line === ts ? [index] : []))
    if (hits.length !== 1) {
      throw new Error(
        `safe-clone.ts: expected exactly one line ${JSON.stringify(ts)} to strip for JavaScript, ` +
          `found ${hits.length}; update jsRewrites in sync-safe-clone.ts`,
      )
    }
    lines[hits[0]] = js
  }
  return lines.join("\n")
}

// expectedBlock is the region a plugin file must carry, given the canonical region.
export function expectedBlock(canonical: string, targetPath: string): string {
  return targetPath.endsWith(".js") ? toJavaScript(canonical) : canonical
}

// replaceBlock returns source with its region replaced by block. Everything outside the markers is
// left byte for byte as it was.
export function replaceBlock(source: string, block: string, label = "source"): string {
  const { start, end } = blockBounds(source, label)
  return source.slice(0, start) + block + source.slice(end)
}

export function canonicalBlock(): string {
  return extractBlock(readFileSync(canonicalPath, "utf8"), relative(repoRoot, canonicalPath))
}

// syncFile rewrites one plugin file's region, or in check mode returns a description of the drift.
// Returns undefined when the file already matches.
export function syncFile(path: string, canonical: string, check: boolean): string | undefined {
  const label = relative(repoRoot, path)
  const source = readFileSync(path, "utf8")
  const next = replaceBlock(source, expectedBlock(canonical, path), label)
  if (next === source) return undefined
  if (check) return `${label}: the shared/safe-clone block differs from plugins/shared/safe-clone.ts`
  writeFileSync(path, next)
  return undefined
}

function main(argv: string[]): number {
  const check = argv.includes("--check")
  const files = argv.filter((arg) => arg !== "--check").map((arg) => resolve(arg))
  const targets = files.length > 0
    ? files
    : consumers.flatMap(({ sourcePath, embeddedPath }) => [sourcePath, embeddedPath])

  const canonical = canonicalBlock()
  const drift: string[] = []
  for (const path of targets) {
    if (!existsSync(path)) {
      drift.push(`${relative(repoRoot, path)}: no such file`)
      continue
    }
    try {
      const problem = syncFile(path, canonical, check)
      if (problem) drift.push(problem)
    } catch (err) {
      drift.push(err instanceof Error ? err.message : String(err))
    }
  }
  if (drift.length === 0) return 0
  for (const line of drift) console.error(line)
  if (check) {
    console.error(
      `Edit the serializer only in plugins/shared/safe-clone.ts, then run \`bun run sync\` in ` +
        `${relative(process.cwd(), dirname(canonicalPath)) || "."} to rewrite every plugin.`,
    )
  }
  return 1
}

if (import.meta.main) process.exit(main(process.argv.slice(2)))
