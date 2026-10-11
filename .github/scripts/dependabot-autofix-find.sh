#!/usr/bin/env bash
# Picks the open Dependabot alerts that still need a fix PR and writes them, grouped by
# (ecosystem, package), to the `groups` step output as a JSON array for the fix job's matrix.
#
# A group is skipped when:
#   - a branch claude/dependabot-alert-<n> exists for any of its alerts (a fix PR is open, or
#     was closed and the branch kept; delete the branch to let the workflow try again),
#   - an open Dependabot PR already bumps the package,
#   - a recent run already tried this exact set of alerts and opened no PR (a skip marker in
#     the Actions cache, which expires after 7 days unused; MANUAL_RUN=true ignores it).
#
# Env: GITHUB_REPOSITORY, GH_TOKEN (needs Dependabot alerts read, contents read,
# pull-requests read, actions read), MAX_GROUPS (default 3), ONLY_ALERT (an alert number),
# MANUAL_RUN (true|false), GITHUB_OUTPUT, GITHUB_STEP_SUMMARY.
set -euo pipefail

repo="${GITHUB_REPOSITORY:?}"
max_groups="${MAX_GROUPS:-3}"
only_alert="${ONLY_ALERT:-}"
manual_run="${MANUAL_RUN:-false}"
out="${GITHUB_OUTPUT:-/dev/stdout}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stderr}"

if [[ -n "$only_alert" && ! "$only_alert" =~ ^[0-9]+$ ]]; then
  echo "::error::alert must be a Dependabot alert number, got: $only_alert"
  exit 1
fi

# --paginate prints one JSON array per page; -s/add joins them (and gives [] for no alerts).
alerts="$(gh api --paginate "repos/$repo/dependabot/alerts?state=open&per_page=100" | jq -s 'add // []')"

# Alerts with no patched release yet have nothing to bump to.
jq -r '.[] | select(.security_vulnerability.first_patched_version == null)
  | "No patched version yet for alert #\(.number) (\(.dependency.package.name)); skipping it."' \
  <<<"$alerts"

groups="$(jq -c --arg only "$only_alert" '
  map(select(.security_vulnerability.first_patched_version != null) | {
    number,
    url: .html_url,
    ecosystem: .dependency.package.ecosystem,
    package: .dependency.package.name,
    manifest: .dependency.manifest_path,
    scope: .dependency.scope,
    severity: .security_advisory.severity,
    ghsa: .security_advisory.ghsa_id,
    cve: .security_advisory.cve_id,
    summary: .security_advisory.summary,
    vulnerable_range: .security_vulnerability.vulnerable_version_range,
    first_patched: .security_vulnerability.first_patched_version.identifier
  })
  | group_by([.ecosystem, .package])
  | map({
      ecosystem: .[0].ecosystem,
      package: .[0].package,
      numbers: (map(.number) | sort),
      manifests: (map(.manifest) | unique),
      alerts: sort_by(.number)
    })
  | map(. + {
      id: (.numbers[0] | tostring),
      key: (.numbers | map(tostring) | join("_"))
    })
  | if $only == "" then . else map(select(.numbers | index($only | tonumber))) end
' <<<"$alerts")"

if [[ -n "$only_alert" && "$groups" == "[]" ]]; then
  echo "::warning::Alert #$only_alert is not an open Dependabot alert with a patched version."
fi

branches="$(gh api --paginate "repos/$repo/git/matching-refs/heads/claude/dependabot-alert-" \
  --jq '.[].ref | sub("^refs/heads/claude/dependabot-alert-"; "")')"
prs="$(gh api --paginate "repos/$repo/pulls?state=open&per_page=100" | jq -s 'add // []
  | map(select(.user.login == "dependabot[bot]") | {number, title, body: (.body // "")})')"

selected='[]'
{
  echo "### Dependabot autofix"
  echo
  echo "| Alerts | Package | Decision |"
  echo "| --- | --- | --- |"
} >>"$summary"

while IFS= read -r group; do
  [[ -n "$group" ]] || continue
  pkg="$(jq -r .package <<<"$group")"
  ecosystem="$(jq -r .ecosystem <<<"$group")"
  key="$(jq -r .key <<<"$group")"
  nums="$(jq -r '.numbers | map("#\(.)") | join(", ")' <<<"$group")"
  decision=""

  while IFS= read -r n; do
    if grep -qx "$n" <<<"$branches"; then
      decision="skipped: branch claude/dependabot-alert-$n exists"
      break
    fi
  done < <(jq -r '.numbers[]' <<<"$group")

  if [[ -z "$decision" ]]; then
    pr="$(jq -r --arg pkg "$pkg" '
      map(select(((.title + " ") | contains(" " + $pkg + " ")) or (.body | contains("`" + $pkg + "`"))))
      | first | .number // empty' <<<"$prs")"
    [[ -z "$pr" ]] || decision="skipped: Dependabot PR #$pr bumps it"
  fi

  if [[ -z "$decision" && "$manual_run" != "true" ]]; then
    tried="$(gh api "repos/$repo/actions/caches?key=dependabot-autofix-skip-$key-" --jq .total_count)"
    [[ "$tried" == "0" ]] || decision="skipped: tried recently with no PR (run the workflow manually to retry)"
  fi

  if [[ -z "$decision" ]]; then
    if (( $(jq length <<<"$selected") >= max_groups )); then
      decision="deferred: $max_groups groups per run"
    else
      decision="fixing"
      selected="$(jq -c --argjson g "$group" '. + [$g]' <<<"$selected")"
    fi
  fi

  echo "$nums ($ecosystem $pkg): $decision"
  echo "| $nums | $ecosystem \`$pkg\` | $decision |" >>"$summary"
done < <(jq -c '.[]' <<<"$groups")

if [[ "$groups" == "[]" ]]; then
  echo "| | | No open Dependabot alerts with a patched version |" >>"$summary"
fi

echo "groups=$selected" >>"$out"
