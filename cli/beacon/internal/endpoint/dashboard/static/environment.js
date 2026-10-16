// Runtime Environment page: renders /api/environment. Read-only, like the rest of the dashboard.
(function () {
  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  const yes = (value) => (value ? '<span class="badge badge-ok">yes</span>' : '<span class="muted">-</span>');
  const rows = (id, items, render, empty) => {
    document.getElementById(id).innerHTML = items.length
      ? items.map((item) => `<tr>${render(item).map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")
      : `<tr><td class="muted" colspan="7">${esc(empty)}</td></tr>`;
  };
  const supervisorTone = { launchd: "badge-ok", app: "badge-muted", unmanaged: "badge-warn" };

  function render(report) {
    const installs = report.installs || [];
    const processes = report.processes || [];
    const plugins = report.plugins || [];
    const jobs = report.launch_jobs || [];
    const warnings = report.warnings || [];
    document.getElementById("environment-meta").textContent =
      `${report.host || "This machine"} · scanned ${new Date(report.generated_at).toLocaleString()}` +
      (report.supported ? "" : " · process and launchd details are collected on macOS only");

    const cards = [
      { label: "Warnings", value: warnings.length, tone: warnings.length ? "warn" : "" },
      { label: "Installs", value: installs.filter((i) => i.kind !== "version").length, hint: `${installs.filter((i) => i.kind === "version").length} kept versions` },
      { label: "Processes", value: processes.length, hint: `${processes.filter((p) => p.supervisor_kind === "unmanaged").length} unmanaged` },
      { label: "Plugins", value: plugins.filter((p) => p.enabled).length, hint: `${plugins.length} installed` },
      { label: "launchd jobs", value: jobs.length, hint: `${jobs.filter((j) => j.running).length} running` },
    ];
    document.getElementById("environment-cards").innerHTML = cards
      .map((card) => `<div class="card ${card.tone ? `card-${card.tone}` : ""}"><span class="muted">${esc(card.label)}</span><span class="value">${esc(card.value)}</span>${card.hint ? `<span class="muted">${esc(card.hint)}</span>` : ""}</div>`)
      .join("");

    rows("environment-warnings", warnings, (w) => [`<span class="badge badge-warn">${esc(w.kind)}</span>`, `<code>${esc(w.subject)}</code>`, esc(w.message)], "No warnings.");
    rows("environment-installs", installs, (i) => [
      esc(i.tool),
      esc(i.kind),
      esc(i.source),
      esc(i.version || ""),
      yes(i.active),
      `<code>${esc(i.path)}</code>${i.broken ? ` <span class="badge badge-danger">missing ${esc(i.target)}</span>` : ""}`,
    ], "No Claude Code or Codex install found.");
    rows("environment-processes", processes, (p) => [
      esc(p.pid),
      esc(p.tool),
      `<code>${esc(p.executable)}</code>${p.executable_missing ? ' <span class="badge badge-danger">deleted</span>' : ""}`,
      esc(p.subcommand || ""),
      esc(p.uptime),
      esc(p.rss_mb),
      `<span class="badge ${supervisorTone[p.supervisor_kind] || "badge-muted"}">${esc(p.supervisor_kind)}</span> ${esc(p.supervisor)}`,
    ], "No Claude Code or Codex process is running.");
    rows("environment-plugins", plugins, (p) => [
      esc(p.runtime),
      esc(p.marketplace ? `${p.name}@${p.marketplace}` : p.name),
      esc(p.version || ""),
      yes(p.enabled),
      (p.mcp_servers || []).map((s) => `${esc(s.name)} <span class="badge ${s.via_ssh ? "badge-warn" : "badge-muted"}">${esc(s.transport)}${s.via_ssh ? "+ssh" : ""}</span>`).join(" "),
    ], "No plugins installed.");
    rows("environment-jobs", jobs, (j) => [
      esc(j.label),
      yes(j.running),
      esc(j.last_exit ?? "-"),
      esc(j.start_interval ? `${j.start_interval}s` : "-"),
      esc(j.recent_errors || 0),
      `<code>${esc(j.program || "")}</code>`,
    ], "No launchd job starts these CLIs.");
  }

  fetch("/api/environment", { headers: { Accept: "application/json" } })
    .then((resp) => {
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return resp.json();
    })
    .then(render)
    .catch((err) => {
      document.getElementById("environment-meta").textContent = `Failed to load environment: ${err.message}`;
    });
})();
