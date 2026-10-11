# Beacon Endpoint Agent Datadog Pack

This pack forwards Beacon endpoint JSONL events into Datadog with the Datadog
Agent's native custom log collection. Beacon still writes one local source of
truth: `runtime.jsonl`. Datadog API keys and site configuration stay in the
Datadog Agent, not in Beacon endpoint configuration.

## Prerequisites

- Datadog Agent installed on the endpoint.
- Log collection enabled in `/opt/datadog-agent/etc/datadog.yaml`:

```yaml
logs_enabled: true
```

## Install

Generate this pack:

```bash
beacon endpoint datadog install-pack --output ./beacon-datadog-pack
```

Install the generated config on macOS:

```bash
sudo mkdir -p /opt/datadog-agent/etc/conf.d/beacon.d
sudo cp ./beacon-datadog-pack/conf.yaml /opt/datadog-agent/etc/conf.d/beacon.d/conf.yaml
sudo chmod 0644 /opt/datadog-agent/etc/conf.d/beacon.d/conf.yaml
sudo launchctl kickstart -k system/com.datadoghq.agent
```

The generated `conf.yaml` points at the Beacon log path selected by the CLI:

- User mode: `~/.beacon/endpoint/logs/runtime.jsonl`
- System mode: `/var/log/beacon-agent/runtime.jsonl`
- Custom mode: the value passed with `--log-path`

For MDM or managed endpoint deployment, prefer Beacon system mode so Datadog can
tail `/var/log/beacon-agent/runtime.jsonl` without per-user home directory ACLs.

## User-Mode macOS Permissions

The Datadog Agent usually runs as `_dd-agent`. A user-mode Beacon log is private
to its user (0600, in directories Beacon creates 0700), so `_dd-agent` cannot
read it by default. Prefer Beacon system mode. To tail a user-mode log anyway,
grant `_dd-agent` traverse access to the parent directories and an inheriting
read ACL on the log directory, so the files rotation creates are covered too:

```bash
# macOS
chmod +a "user:_dd-agent allow list,search,read,file_inherit" ~/.beacon/endpoint/logs
# Linux (dd-agent): the default ACL covers new files; Beacon keeps its mask readable
setfacl -m u:dd-agent:rx ~/.beacon/endpoint/logs
setfacl -d -m u:dd-agent:r ~/.beacon/endpoint/logs
setfacl -m u:dd-agent:r ~/.beacon/endpoint/logs/runtime.jsonl
```

Beacon never widens an existing log and only removes its "other" bits, so a
grant made this way survives every append and rotation.

## Validate

Write a fresh Beacon validation event:

```bash
beacon endpoint datadog validate
```

Check the Datadog Agent status:

```bash
sudo datadog-agent status
```

The Logs Agent section should show logs processed and sent. In Datadog Log
Explorer, search for:

```text
service:beacon-endpoint-agent vendor:beacon product:endpoint-agent
```

You can also search for the validation event without requiring a custom Datadog
facet or parsing pipeline:

```text
service:beacon-endpoint-agent "Beacon endpoint datadog validation event"
```

## Content Handling

Beacon forwards retained prompt text, tool input, command output, and related
local telemetry to Datadog subject to Beacon's secret redaction, sanitization,
truncation, and event-size limits.

## OpenTelemetry Note

Datadog's DDOT Collector is a good fit for OTel-first Linux or Kubernetes
deployments, but Beacon's macOS endpoint v0 uses native Datadog Agent file log
collection because it is the supported host path for tailing local JSONL files.
