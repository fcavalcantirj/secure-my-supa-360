// HTML report generator — fully self-contained (inline CSS, no external CDN).
// Consumes the exact JSON result from audit.js / report <file.json>.
// Spec entry 30: renders the FULL finding schema — evidence, probe bytes/sample,
// confidence badge, fix.sql[] + rollback_sql[], management_api_action,
// dashboard_action, suppressed section. No CDN assets so it works offline.
// Never auto-runs as part of audit (spec entry 2) — only via `report` subcommand.

const SEVERITY_STYLE = {
  critical: { bg: "#fef2f2", border: "#dc2626", badge: "#dc2626", text: "#991b1b" },
  high:     { bg: "#ffedd5", border: "#f97316", badge: "#f97316", text: "#9a3412" },
  medium:   { bg: "#fef9c3", border: "#eab308", badge: "#eab308", text: "#713f12" },
  low:      { bg: "#eff6ff", border: "#3b82f6", badge: "#3b82f6", text: "#1d4ed8" },
  info:     { bg: "#f5f5f5", border: "#6b7280", badge: "#6b7280", text: "#374151" },
};

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function confidenceBadge(confidence) {
  const isConfirmed = confidence === "confirmed";
  const bg = isConfirmed ? "#fee2e2" : "#e0f2fe";
  const color = isConfirmed ? "#b91c1c" : "#0369a3";
  const label = isConfirmed ? "CONFIRMED" : "INFERRED";
  const title = isConfirmed
    ? "Confirmed by active anon-key probe (we fetched the data)"
    : "Inferred from metadata / grants (not live-probed)";
  return `<span class="conf-badge" style="background:${bg};color:${color}" title="${title}">${label}</span>`;
}

function probeBlock(probe) {
  if (!probe || probe.status === null) return "";
  const bytes = probe.bytes ?? 0;
  const rowCount = probe.sample?.row_count ?? 0;
  const columns = probe.sample?.columns;
  const isLeak = probe.status === 200 && (rowCount > 0 || bytes > 0);
  const statusLabel = probe.status === 200
    ? "HTTP 200 (data returned)"
    : probe.status === 42501
      ? "HTTP 42501 (blocked)"
      : `HTTP ${probe.status}`;
  const cls = isLeak ? "probe-leak" : "probe-safe";
  let colsHtml = "";
  if (Array.isArray(columns) && columns.length) {
    colsHtml = ` · Columns visible: <code>${escapeHtml(columns.join(", "))}</code>`;
  }
  return `
    <div class="${cls}">
      <strong>★ Active probe:</strong> ${statusLabel} · ${rowCount} row(s) · ${bytes} bytes leaked${colsHtml}
    </div>`;
}

function evidenceBlock(evidence) {
  if (!evidence || Object.keys(evidence).length === 0) return "";
  const pretty = escapeHtml(JSON.stringify(evidence, null, 2));
  return `
    <details class="evidence-details">
      <summary>Evidence</summary>
      <pre><code>${pretty}</code></pre>
    </details>`;
}

function fixBlock(f, idx) {
  const fix = f.fix || {};
  const sqlArr = Array.isArray(fix.sql) ? fix.sql : [];
  const rollbackArr = Array.isArray(fix.rollback_sql) ? fix.rollback_sql : [];
  const mgmt = fix.management_api_action;
  const dash = fix.dashboard_action;
  const needsSr = fix.requires_service_role;

  const allSql = sqlArr.map((s) => `-- ${f.check} (${f.target})\n${s}`).join("\n\n");
  const sqlId = `fix-${idx}`;
  const rollbackId = `rollback-${idx}`;

  let mgmtHtml = "";
  if (mgmt) {
    const bodyJson = escapeHtml(JSON.stringify(mgmt.body || {}, null, 2));
    mgmtHtml = `
      <div class="action-block">
        <strong>Management API action:</strong> ${escapeHtml(mgmt.method || "PATCH")} ${escapeHtml(mgmt.path || "")}
        ${mgmt.body ? `<pre><code>${bodyJson}</code></pre>` : ""}
      </div>`;
  }

  let dashHtml = "";
  if (dash) {
    dashHtml = `<div class="action-block"><strong>Dashboard action:</strong> ${escapeHtml(dash)}</div>`;
  }

  let srNote = "";
  if (needsSr) {
    srNote = `<div class="sr-note">⚠ This fix requires a service_role key (SUPABASE_SERVICE_ROLE_KEY).</div>`;
  }

  return `
    <div class="fix-block">
      <details>
        <summary>Fix SQL (copy & run in Supabase SQL editor)</summary>
        <pre><code id="${sqlId}">${escapeHtml(sqlArr.join("\n\n"))}</code></pre>
        <button onclick="copyToClipboard('${sqlId}')">Copy</button>
        ${srNote}
      </details>
      ${rollbackArr.length > 0
        ? `
        <details>
          <summary>Rollback SQL (undo this fix)</summary>
          <pre class="rollback"><code id="${rollbackId}">${escapeHtml(rollbackArr.join("\n\n"))}</code></pre>
          <button onclick="copyToClipboard('${rollbackId}')">Copy</button>
        </details>`
        : '<div class="no-rollback">No automated rollback available — manual revert required.</div>'
      }
      ${mgmtHtml}
      ${dashHtml}
    </div>`;
}

function findingCard(f, idx) {
  const style = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.info;
  return `
  <div class="finding-card" style="background:${style.bg};border-left:4px solid ${style.border};color:${style.text}">
    <div class="finding-header">
      <div>
        <span class="severity-badge" style="background:${style.badge}">${escapeHtml(f.severity.toUpperCase())}</span>
        ${confidenceBadge(f.confidence)}
        <span class="check-id">${escapeHtml(f.check)}</span>
      </div>
      <code class="target-code">${escapeHtml(f.target)}</code>
    </div>
    ${f.title
      ? `<h3 class="finding-title">${escapeHtml(f.title)}</h3>`
      : ""
    }
    ${f.explain
      ? `<p class="finding-explain">${escapeHtml(f.explain)}</p>`
      : ""
    }
    ${probeBlock(f.probe)}
    ${evidenceBlock(f.evidence)}
    ${f.details
      ? `
    <details class="details">
      <summary>Details</summary>
      <pre><code>${escapeHtml(JSON.stringify(f.details, null, 2))}</code></pre>
    </details>`
      : ""
    }
    ${fixBlock(f, idx)}
    ${Array.isArray(f.references) && f.references.length > 0
      ? `
    <div class="references">
      <strong>References:</strong>
      ${f.references.map((r) => `<a href="${escapeHtml(r)}">${escapeHtml(r)}</a>`).join(" ")}
    </div>`
      : ""}
  </div>`;
}

function severityBarChart(summary) {
  const entries = [
    { label: "Critical", val: summary.by_severity.critical, color: "#dc2626" },
    { label: "High", val: summary.by_severity.high, color: "#f97316" },
    { label: "Medium", val: summary.by_severity.medium, color: "#eab308" },
    { label: "Low", val: summary.by_severity.low, color: "#3b82f6" },
    { label: "Info", val: summary.by_severity.info, color: "#6b7280" },
  ];
  const maxVal = Math.max(...entries.map((e) => e.val), 1);
  const barHeight = (val) => Math.max((val / maxVal) * 120, val > 0 ? 4 : 0);
  return `
    <div class="chart">
      <h2>Findings by severity</h2>
      <div class="chart-bars">
        ${entries.map((e) => `
        <div class="chart-col">
          <div class="chart-val" style="height:${barHeight(e.val)}px;background:${e.color}"></div>
          <span class="chart-label">${e.val}</span>
          <span class="chart-name">${e.label}</span>
        </div>`).join("")}
      </div>
    </div>`;
}

const INLINE_CSS = `
  body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#f9fafb;color:#111827}
  .maxw{max-width:1000px;margin:0 auto;padding:24px}
  .header{background:linear-gradient(135deg,#059669,#0d9488);color:#fff;padding:32px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  .header h1{font-size:28px;margin:0 0 8px}
  .header p{margin:2px 0;color:#d1fae5}
  .grade-box{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}
  .grade-card{background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:90px}
  .grade-card .grade-txt{font-size:36px;font-weight:700}
  .grade-card .grade-sub{font-size:12px;color:#6b7280}
  .badge-critical,.badge-high,.badge-medium,.badge-low,.badge-info{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}
  .banner{padding:14px;border-radius:8px;margin:20px 0;font-weight:600;font-size:14px}
  .banner-red{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
  .banner-green{background:#dcfce8;color:#166534;border:1px solid #86efac}
  .banner-gray{background:#f3f4f6;color:#374151;border:1px solid #d1d5db}
  .coverage{bg:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin:20px 0}
  .coverage h2{font-size:18px;margin:0 0 12px}
  .coverage-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;text-align:center}
  .coverage-item .cov-val{font-size:24px;font-weight:700;color:#374151}
  .coverage-item .cov-label{font-size:11px;color:#6b7280}
  .chart{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin:20px 0}
  .chart h2{font-size:18px;margin:0 0 12px}
  .chart-bars{display:flex;align-items:flex-end;gap:12px;height:140px;align-items:flex-end}
  .chart-col{display:flex;flex-direction:column;align-items:center;flex:1}
  .chart-val{width:100%;border-radius:4px 4px 0 0}
  .chart-label{font-size:14px;font-weight:700}
  .chart-name{font-size:11px;color:#6b7280}
  .finding-card{background:#fff;border-radius:8px;padding:16px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.1);border-left:4px solid #ccc}
  .finding-header{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px}
  .severity-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}
  .conf-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-left:6px}
  .check-id{font-size:11px;color:#6b7280;margin-left:auto}
  .target-code{background:#f1f5f9;padding:2px 8px;border-radius:4px;font-size:12px}
  .finding-title{font-size:20px;margin:8px 0}
  .finding-explain{font-size:14px;margin:8px 0;line-height:1.5}
  .probe-leak{background:#fee2e2;color:#991b1b;padding:8px;border-radius:6px;margin:8px 0;font-size:13px}
  .probe-safe{background:#dcfce8;color:#166534;padding:8px;border-radius:6px;margin:8px 0;font-size:13px}
  .evidence-details,.details{margin:8px 0}
  .evidence-details summary,.details summary{cursor:pointer;font-weight:600;font-size:13px}
  .evidence-details pre,.details pre,pre{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px;overflow-x:auto;font-size:12px}
  .fix-block{margin-top:12px}
  .fix-block details{margin:8px 0}
  .fix-block summary{cursor:pointer;font-weight:600;font-size:13px;color:#059669}
  .rollback{background:#0f172a;color:#4ade80}
  .no-rollback{font-size:12px;color:#9a3412;background:#ffedd5;padding:6px;border-radius:4px;margin:6px 0}
  .action-block{font-size:13px;margin:8px 0;padding:8px;background:#f0fdf4;border-radius:6px}
  .sr-note{font-size:12px;color:#9a3412;background:#ffedd5;padding:6px;border-radius:4px}
  .references{font-size:13px;margin-top:8px}
  .references a{color:#2563eb}
  .all-fixes{background:#1e293b;color:#4ade80;padding:16px;border-radius:8px;overflow-x:auto;font-size:12px;margin:16px 0}
  .no-findings{background:#dcfce8;border:1px solid #86efac;color:#166534;padding:32px;border-radius:8px;text-align:center}
  .footer{text-align:center;color:#9ca3af;font-size:12px;margin-top:24px}
`;

export function renderHtml(result) {
  const {
    project_name, project_ref, region, generated_at, summary, findings,
    n_tables_scanned,
    scan_complete,
    scan_failures,
    errors,
    timed_out,
    active_probe,
  } = result;

  const total = findings.length;
  const confirmed = summary.confirmed || 0;
  const inferred = summary.inferred || 0;
  const suppressed = summary.suppressed || 0;

  // WO-13: a scan that failed, timed out, or scanned zero tables must NOT
  // show a green A+ grade or a "clean" banner. Derive the failure list
  // from scan_failures (set by audit.js) or fall back to errors[].check.
  const scanIncomplete =
    scan_complete === false ||
    timed_out === true ||
    (n_tables_scanned ?? 0) === 0;
  const failureEntries = Array.isArray(errors) ? errors : [];
  const failureList = Array.isArray(scan_failures)
    ? scan_failures
    : failureEntries.map((e) => (e && e.check) || "unknown");

  // WO-13: probe banner branches on active_probe.enabled, NOT finding counts,
  // so passive runs don't emit "Active probe ran".
  const probeEnabled = !!(active_probe && active_probe.enabled);
  const probeBanner = probeEnabled
    ? (confirmed > 0
      ? `<div class="banner banner-red">★ Active anon-key probe confirmed ${confirmed} of ${confirmed + inferred} suspected leak(s) live — we fetched the data with the anon key.</div>`
      : `<div class="banner banner-gray">▸ Active probe ran — ${inferred} finding(s) inferred from metadata. ${confirmed} confirmed live.</div>`)
    : `<div class="banner banner-gray">▸ Passive scan (no active anon-key probe). Run with --probe to confirm leaks live.</div>`;

  // Mode banner: show audit mode + history/probe flags so the reader knows
  // whether findings are confirmed or inferred-only.
  const modeLabel = result.mode === "audit-active" ? "ACTIVE (anon-key probe enabled)" : result.mode === "audit-passive" ? "PASSIVE (metadata scan only)" : "DISCOVER";
  const modeColor = result.mode === "audit-active" ? "#991b1b" : "#374151";
  const historyNote = result.history ? (result.history.history_available
    ? ` · History: available (excluded ${result.history.excluded_count || 0} probe/internal rows)`
    : ` · History: pg_stat_statements absent`) : "";
  const modeBanner = `<div class="banner" style="background:#f1f5f9;border:1px solid #a0aec0;color:#1e293b">📊 Mode: <strong>${modeLabel}</strong>${historyNote}</div>`;

  const sev = summary.by_severity;
  const score = Math.max(0, 100 - (sev.critical * 20 + sev.high * 10 + sev.medium * 4 + sev.low * 1));
  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";
  const gradeColor = score >= 85 ? "#16a34a" : score >= 50 ? "#ca8a04" : "#dc2626";

  const allFixSql = findings
    .filter((f) => !f.suppressed)
    .map((f) => {
      const sql = Array.isArray(f.fix?.sql) ? f.fix.sql : [];
      const title = f.title || f.check;
      return `-- ${title} (${f.target})\n${sql.join("\n")}`;
    })
    .join("\n\n");

  // Separate suppressed vs active findings
  const activeFindings = findings.filter((f) => !f.suppressed);
  const suppressedFindings = findings.filter((f) => f.suppressed);

  // WO-13: incomplete-scan banner (red, lists scan_failures + error messages)
  const incompleteBanner = scanIncomplete
    ? `<div class="banner banner-red">
        ⚠ INCOMPLETE SCAN — ${failureList.length} check(s) could not run
        <ul style="margin:8px 0 0 20px;padding:0;font-size:13px">
          ${failureList.map((f, i) => `<li>${escapeHtml(f)}${failureEntries[i] ? " — " + escapeHtml(failureEntries[i].error || "") : ""}</li>`).join("")}
        </ul>
      </div>`
    : "";

  // WO-13: grade + score suppressed entirely when the scan did not complete
  const gradeSection = scanIncomplete
    ? `<div class="banner banner-gray">No grade assigned — ${failureList.length} check(s) could not run. Fix the errors above and re-run.</div>`
    : `<div class="grade-box">
        <div class="grade-card">
          <div class="grade-txt" style="color:${gradeColor}">${grade}</div>
          <div class="grade-sub">Score: ${score}/100</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#dc2626">${sev.critical}</div>
          <div class="grade-sub">Critical</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#f97316">${sev.high}</div>
          <div class="grade-sub">High</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#eab308">${sev.medium}</div>
          <div class="grade-sub">Medium</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#3b82f6">${sev.low}</div>
          <div class="grade-sub">Low</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#6b7280">${sev.info}</div>
          <div class="grade-sub">Info</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#b91c1c">C: ${confirmed}</div>
          <div class="grade-sub">Confirmed</div>
        </div>
        <div class="grade-card">
          <div class="grade-val" style="color:#0369a3">I: ${inferred}</div>
          <div class="grade-sub">Inferred</div>
        </div>
      </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Supabase Security Report — ${escapeHtml(project_name)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>${INLINE_CSS}</style>
</head>
<body>
  <div class="maxw">
    <!-- Header -->
    <div class="header">
      <h1>Supabase Security Report</h1>
      <p><strong>Project:</strong> ${escapeHtml(project_name || "(unnamed)")} <span class="opacity-80">(${escapeHtml(project_ref)})</span></p>
      <p><strong>Region:</strong> ${escapeHtml(region || "—")} · <strong>Scanned:</strong> ${escapeHtml(new Date(generated_at).toLocaleString())}</p>
    </div>

    <!-- WO-13: incomplete scan banner — shown at the very top, overrides everything -->
    ${incompleteBanner}

    ${modeBanner}
    ${probeBanner}

    <!-- Score + Grade (suppressed when scan incomplete — WO-13) -->
    ${gradeSection}

    <!-- Coverage -->
    <div class="coverage">
      <h2>Coverage</h2>
      <div class="coverage-grid">
        <div class="coverage-item"><div class="cov-val">${n_tables_scanned ?? total}</div><div class="cov-label">Tables scanned</div></div>
        <div class="coverage-item"><div class="cov-val">${sev.critical + sev.high + sev.medium + sev.low + sev.info}</div><div class="cov-label">Total findings</div></div>
        <div class="coverage-item"><div class="cov-val">${activeFindings.length}</div><div class="cov-label">Active</div></div>
        <div class="coverage-item"><div class="cov-val">${suppressedFindings.length}</div><div class="cov-label">Suppressed</div></div>
      </div>
    </div>

    <!-- Severity chart (CSS only, no CDN) -->
    ${total > 0 ? severityBarChart(summary) : ""}

    <!-- Active findings -->
    ${activeFindings.length > 0
      ? `
    <div>
      <h2 style="font-size:24px;margin:16px 0 12px">Findings (${activeFindings.length})</h2>
      ${activeFindings.map((f, i) => findingCard(f, i)).join("")}
    </div>

    <!-- All fixes bundle -->
    <div class="all-fixes">
      <h2 style="color:#94a3b8;font-size:16px;margin:0 0 8px">Apply all fixes (single SQL script)</h2>
      <p style="color:#94a3b8;font-size:12px;margin:0 0 8px">Copy and run in Supabase Dashboard → SQL Editor. Review each statement before executing.</p>
      <pre><code id="all-fixes">${escapeHtml(allFixSql)}</code></pre>
    </div>`
      : scanIncomplete
        ? `<div class="banner banner-gray">No findings could be produced — the scan did not complete. Fix the errors above and re-run.</div>`
        : `
    <div class="no-findings">
      <h2>No security issues found.</h2>
      <p>Your Supabase project passes all checks.</p>
    </div>`
    }

    <!-- Suppressed findings -->
    ${suppressedFindings.length > 0
      ? `
    <div style="margin-top:24px;padding:16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
      <h2 style="font-size:20px;margin:0 0 12px">Suppressed findings (${suppressedFindings.length})</h2>
      ${suppressedFindings.map((f) => {
        const s = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.info;
        const dash = f.fix?.dashboard_action;
        return `
      <div style="margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e2e8f0">
        <span class="severity-badge" style="background:${s.badge}">${escapeHtml(f.severity.toUpperCase())}</span>
        <strong style="margin-left:6px">${escapeHtml(f.title || f.check)}</strong>
        <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:12px">${escapeHtml(f.target)}</code>
        ${f.suppressed_reason ? `<span style="font-size:12px;color:#6b7280"> — ${escapeHtml(f.suppressed_reason)}</span>` : ""}
        ${dash ? `<div style="font-size:12px;color:#475569;margin-top:4px"><strong>Dashboard:</strong> ${escapeHtml(dash)}</div>` : ""}
      </div>`;
      }).join("")}
    </div>`
      : ""
    }

    <!-- Footer -->
    <div class="footer">
      Generated by <a href="https://github.com/fcavalcantirj/secure-my-supa-360" style="color:#059669">supabase-security</a>
      · Open source (MIT) · Run locally, your token never leaves your machine.
    </div>
  </div>
  <script>
    function copyToClipboard(id) {
      const el = document.getElementById(id);
      if (el) el.select(); navigator.clipboard.writeText(el.textContent).catch(()=>{});
    }
  </script>
</body>
</html>`;
}
