# tracegen

Generates **simulated** agent sessions that reproduce security vulnerabilities, checks that
Beacon's open threat rules (`rules/`) catch each one, and publishes them to beacon.sh as
shared traces with the detections inline. Use it to backfill Discover with showcase
traces.

It is a maintainer tool inside the `cli/beacon` module (so it reuses the real share
client and projection). It is not part of the shipped `beacon` binary.

## Pipeline

```
scenarios/*.yaml ──Build──▶ endpoint events ──Detect (rules/)──▶ findings
                                   │                                 │
                                   └──────────── Annotate ◀──────────┘
                                                    │  one policy.detected event per finding,
                                                    ▼  just after its last evidence event
                                 BuildShareBundle (same projection as `beacon share`)
                                                    │
                                                    ▼
                            PUT /v1/traces/{id} + POST /events/batch
```

- **Build** turns each step into what a real hook capture writes: a `tool.invoked` and its
  completion (`file.read`, `command.executed`, `mcp.tool_invoked`, ...) sharing a
  `tool_call_id`, so beacon.sh pairs them.
- **Detect** runs the full corpus, the same evaluation as `beacon scan --rules rules`.
- **Verify** fails a scenario if an expected rule does not fire, **or** if an unlisted rule
  fires (unless `allow_other: true`). The test suite runs this on every scenario, so a
  rule change that stops catching a showcased attack fails CI.
- **Annotate** adds `policy.detected` events (`event.fidelity=inferred`, `policy.id` = rule
  id). beacon.sh shows them as "Policy: detected" lines with the severity, rule id,
  reason and rule title.

## Commands

Run from `cli/beacon`:

```bash
go run ./tools/tracegen list
go run ./tools/tracegen verify
go run ./tools/tracegen build -out /tmp/tracegen          # runtime.jsonl, findings.json, payload.json per scenario
go run ./tools/tracegen publish -dry-run                  # print exactly what would be sent
go run ./tools/tracegen publish                           # upload as direct (link-only) traces
go run ./tools/tracegen publish -visibility public -force-visibility -yes   # list on Discover
```

`-only id1,id2` limits any command to some scenarios. `build` output is plain Beacon
JSONL, so you can confirm it independently:

```bash
beacon scan --rules ../../rules --log-path /tmp/tracegen/<id>/runtime.jsonl
```

### Credentials

`publish` resolves a credential like `beacon share`: `-key`, then a current
`beacon login` with `traces:write`, then `BEACON_API_KEY`. Use a key for the account that
should own the showcase traces. `-base-url` targets another deployment (staging).

### Publishing workflow

1. `publish` (default `direct`) and review each link on beacon.sh.
2. `publish -visibility public -force-visibility -yes` to list them on Discover. Without
   `-force-visibility`, an existing trace keeps the visibility it has on beacon.sh.

Re-publishing is an upsert: the external id is derived from the scenario id and event ids
from event content, so an edited scenario replaces its trace in place.

## Labeling

Generated traces are marked three ways, because Discover describes its feed as real
community sessions:

- the title is prefixed `Simulated: ` (`-title-prefix` changes it);
- the trace `source` is `api` and `provenance.source` is `beacon-tracegen`;
- everything runs in a fake home (`/home/dev`) on host `tracegen`, scrubbed by the share
  projection like any real session.

Use only reserved example domains (`*.attacker.example`, RFC 2606) and obviously fake
secrets. beacon.sh redacts secret-shaped strings anyway.

## Writing a scenario

Create `scenarios/<id>.yaml` (the file name must equal `id`):

```yaml
id: my-new-attack
title: One-line headline shown on Discover
summary: >
  What happens and what Beacon flags.
vulnerability:
  class: Indirect prompt injection leading to ...
  owasp_llm: LLM01          # optional
  mitre_atlas: AML.T0051    # optional
  references: [https://...]
harness: claude_code         # normalized runtime name the trace is attributed to
model: claude-sonnet-4-5
project: payments-api        # directory name the session runs in
start: 2026-09-01T15:00:00Z  # optional
expect:
  rules: [curl-pipe-to-shell]
  allow_other: false         # default: any extra finding fails verify
steps:                       # must start with a prompt; exactly one kind per step
  - prompt: user message
  - agent: assistant message
  - thinking: assistant reasoning
  - read:    {path: README.md, content: "file contents"}       # relative = under the project
  - fetch:   {url: https://..., content: "page text"}
  - command: {command: "curl ... | sh", output: "...", exit_code: 0, description: "..."}
  - edit:    {path: src/app.ts, diff: "unified diff"}
  - mcp:     {server: https://..., tool: name, description: "...", arguments: {...}, result: "..."}
  - approval: {decision: denied, reason: "...", command: "rm -rf ..."}
  - event:   {event: {action: ...}, ...}   # escape hatch: raw event in rule-fixture shape
  - after: 30s                             # any step: delay since the previous one (default 4s)
    command: {command: ...}
```

Start with `expect.rules: []`-style guesses, run `verify`, and read what fired: it lists
every expected rule that did not fire and every rule that fired unexpectedly. Rule
fixtures under `rules/<category>/*.rule.yaml` are a good source of realistic payloads.
Use `~/` paths for files in the home directory.

## Scenarios

| id | class | rules showcased |
|----|-------|-----------------|
| `approval-denied-command-run-anyway` | Approval bypass (excessive agency) | approval-denied-command-executed-anyway, recursive-root-delete |
| `cloud-metadata-credential-theft` | SSRF-style cloud metadata credential theft | cloud-metadata-endpoint-access, cloud-metadata-then-egress, link-local-internal-target-fetch |
| `poisoned-mcp-tool-ssh-key-theft` | MCP tool poisoning → credential exfiltration | credential-file-read, external-mcp-tool-call, mcp-poisoned-tool-description, secret-read-then-external-mcp, secret-read-then-mcp-tool-handoff |
| `readme-injection-env-exfiltration` | Indirect prompt injection → credential exfiltration | credential-file-read, credentials-in-curl-data, curl-pipe-to-shell, indirect-injection-in-tool-result, secret-read-then-egress |
