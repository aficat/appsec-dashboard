(() => {
  const report = window.__REPORT__ || { findings: [], recommendations: [], summary: {} };
  const meta = window.__META__ || {};
  const findingById = new Map(
    (Array.isArray(report && report.findings) ? report.findings : []).map((f) => [String((f && f.id) || ""), f])
  );
  let rows = [];
  const filters = document.getElementById("filters");
  const chatLog = document.getElementById("chatLog");
  const chatForm = document.getElementById("chatForm");
  const chatInput = document.getElementById("chatInput");
  const chatWidget = document.getElementById("chatWidget");
  const chatToggle = document.getElementById("chatToggle");
  const chatClose = document.getElementById("chatClose");
  const themeToggle = document.getElementById("themeToggle");
  const refreshDashboardBtn = document.getElementById("refreshDashboardBtn");
  const viewJsonLink = document.getElementById("viewJsonLink");
  const jsonModal = document.getElementById("jsonModal");
  const jsonCloseBtn = document.getElementById("jsonCloseBtn");
  const jsonCopyBtn = document.getElementById("jsonCopyBtn");
  const jsonModalPre = document.getElementById("jsonModalPre");
  const workflowStatus = document.getElementById("workflowStatus");
  const workflowPct = document.getElementById("workflowPct");
  const workflowMeta = document.getElementById("workflowMeta");
  const workflowError = document.getElementById("workflowError");
  const workflowSteps = workflowStatus ? Array.from(workflowStatus.querySelectorAll(".workflowStep")) : [];
  const runPipelineBtn = document.getElementById("runPipelineBtn");
  const stopPipelineBtn = document.getElementById("stopPipelineBtn");
  const compareReportsBtn = document.getElementById("compareReportsBtn");
  const compareModal = document.getElementById("compareModal");
  const compareCloseBtn = document.getElementById("compareCloseBtn");
  const comparePrevSelect = document.getElementById("comparePrevSelect");
  const compareRunBtn = document.getElementById("compareRunBtn");
  const compareGrid = document.getElementById("compareGrid");
  const compareMeta = document.getElementById("compareMeta");
  let workflowPollTimer = null;

  function normalizeTitleKey(s) {
    return String(s || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function getSeverityRank(sevRaw) {
    const sev = String(sevRaw || "").toLowerCase();
    if (sev === "critical") return 4;
    if (sev === "high") return 3;
    if (sev === "medium") return 2;
    if (sev === "low") return 1;
    return 0;
  }

  function titleCaseSeverity(sevRaw) {
    const s = String(sevRaw || "").trim().toLowerCase();
    if (!s) return "Other";
    if (s === "critical") return "Critical";
    if (s === "high") return "High";
    if (s === "medium") return "Medium";
    if (s === "low") return "Low";
    return s.slice(0, 1).toUpperCase() + s.slice(1);
  }

  function groupFindingsBySimilarTitle() {
    const tbody = document.querySelector("#findingsTable tbody");
    if (!tbody) return { groups: new Map(), ungrouped: new Set() };

    const allRows = Array.from(tbody.querySelectorAll("tr.row"));
    const byKey = new Map();

    allRows.forEach((r) => {
      const titleCell = r.querySelector("td.titleCell");
      const title = titleCell ? String(titleCell.textContent || "").trim() : "";
      const key = normalizeTitleKey(title);
      if (!key) return;
      const arr = byKey.get(key) || [];
      arr.push(r);
      byKey.set(key, arr);
      r.dataset.titleKey = key;
    });

    const groups = new Map();
    const ungrouped = new Set(allRows);

    byKey.forEach((members, key) => {
      if (!Array.isArray(members) || members.length < 2) return;

      // Create a group header row right before the first member row.
      const first = members[0];
      const firstTitleCell = first.querySelector("td.titleCell");
      const titleText = firstTitleCell ? String(firstTitleCell.textContent || "").trim() : "Untitled";

      let groupSev = "other";
      let bestRank = -1;
      members.forEach((m) => {
        const r = getSeverityRank(m.getAttribute("data-sev") || "other");
        if (r > bestRank) {
          bestRank = r;
          groupSev = String(m.getAttribute("data-sev") || "other");
        }
      });

      const groupRow = document.createElement("tr");
      groupRow.className = "groupRow";
      groupRow.setAttribute("data-group-key", key);
      groupRow.setAttribute("data-sev", groupSev);
      groupRow.setAttribute("aria-expanded", "false");

      const locations = members
        .map((m) => {
          const loc = m.querySelector("td.locCell code");
          return loc ? String(loc.textContent || "").trim() : "";
        })
        .filter(Boolean);
      const uniqueLocations = Array.from(new Set(locations));

      const confVals = members
        .map((m) => {
          const id = String(m.getAttribute("data-id") || "");
          const f = id ? findingById.get(id) : null;
          return f && typeof f.validation_confidence === "number" ? f.validation_confidence : null;
        })
        .filter((n) => typeof n === "number");
      const avgConf = confVals.length ? confVals.reduce((a, b) => a + b, 0) / confVals.length : null;

      groupRow.innerHTML = `
        <td>
          <span class="sev sev--${esc(groupSev)}">${esc(titleCaseSeverity(groupSev))}</span>
        </td>
        <td class="titleCell" title="${esc(titleText)}">
          <span class="groupRow__title">${esc(titleText)}</span>
          <span class="groupRow__meta muted">(${members.length} findings)</span>
        </td>
        <td class="locCell">
          <code class="groupRow__loc">${esc(uniqueLocations.slice(0, 2).join(" • "))}${uniqueLocations.length > 2 ? esc(` • +${uniqueLocations.length - 2} more`) : ""}</code>
        </td>
        <td>${avgConf == null ? `<span class="muted">—</span>` : `<code>${avgConf.toFixed(2)}</code>`}</td>
      `.trim();

      tbody.insertBefore(groupRow, first);

      // Collapse members by default (but keep in DOM so per-finding detail still works).
      members.forEach((m) => {
        m.dataset.groupKey = key;
        const detailRow = m.nextElementSibling;
        m.style.display = "none";
        if (detailRow && detailRow.classList.contains("detailRow")) {
          detailRow.style.display = "none";
          detailRow.hidden = true;
          detailRow.dataset.groupKey = key;
        }
        ungrouped.delete(m);
      });

      groups.set(key, { key, groupRow, members });
    });

    return { groups, ungrouped };
  }

  // Build grouped view once on load.
  const grouping = groupFindingsBySimilarTitle();
  rows = Array.from(document.querySelectorAll("#findingsTable tbody tr.row"));

  // Stabilize workflow step titles: some browser extensions / prior DOM mutations can
  // accidentally append extra text nodes. Cache the template titles and re-apply them.
  workflowSteps.forEach((el) => {
    const titleEl = el.querySelector(".workflowStep__title");
    if (!titleEl) return;
    const base = String(titleEl.textContent || "").trim();
    if (base) el.dataset.baseTitle = base;
  });

  function getSystemTheme() {
    try {
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch {
      return "dark";
    }
  }

  function getSavedTheme() {
    try {
      const t = localStorage.getItem("dashboard_theme");
      return t === "light" || t === "dark" ? t : null;
    } catch {
      return null;
    }
  }

  function setTheme(theme) {
    const t = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    if (themeToggle) {
      themeToggle.setAttribute("aria-pressed", t === "dark" ? "true" : "false");
      const nextLabel = t === "dark" ? "Switch to light mode" : "Switch to dark mode";
      themeToggle.setAttribute("title", nextLabel);
      themeToggle.setAttribute("aria-label", nextLabel);
      const sr = document.getElementById("themeToggleText");
      if (sr) sr.textContent = nextLabel;
    }
  }

  function persistTheme(theme) {
    try {
      localStorage.setItem("dashboard_theme", theme);
    } catch {
      // ignore
    }
  }

  // Initialize theme early.
  setTheme(getSavedTheme() || getSystemTheme());
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
      const next = current === "dark" ? "light" : "dark";
      setTheme(next);
      persistTheme(next);
    });
  }

  function closeAllAccordions() {
    rows.forEach((r) => {
      r.classList.remove("row--active");
      r.setAttribute("aria-expanded", "false");
      const detailRow = r.nextElementSibling;
      if (detailRow && detailRow.classList.contains("detailRow")) {
        detailRow.hidden = true;
      }
    });
  }

  function toggleAccordion(row) {
    const detailRow = row.nextElementSibling;
    if (!detailRow || !detailRow.classList.contains("detailRow")) return;

    const open = row.getAttribute("aria-expanded") === "true";
    closeAllAccordions();
    if (!open) {
      row.classList.add("row--active");
      row.setAttribute("aria-expanded", "true");
      detailRow.hidden = false;
    }
  }

  function applyFilter(sev) {
    const wanted = (sev || "all").toLowerCase();
    closeAllAccordions();

    // Ungrouped: behave exactly as before.
    grouping.ungrouped.forEach((r) => {
      const rowSev = (r.getAttribute("data-sev") || "other").toLowerCase();
      const show = wanted === "all" ? true : rowSev === wanted;
      r.style.display = show ? "" : "none";
      const detailRow = r.nextElementSibling;
      if (detailRow && detailRow.classList.contains("detailRow")) {
        detailRow.style.display = show ? "" : "none";
        detailRow.hidden = true;
      }
    });

    // Grouped: show group header if any member matches. Members only show when expanded.
    grouping.groups.forEach((g) => {
      const groupRow = g.groupRow;
      const expanded = groupRow.getAttribute("aria-expanded") === "true";
      const matchingMembers = g.members.filter((m) => {
        const rowSev = (m.getAttribute("data-sev") || "other").toLowerCase();
        return wanted === "all" ? true : rowSev === wanted;
      });

      const showGroup = matchingMembers.length > 0;
      groupRow.style.display = showGroup ? "" : "none";

      g.members.forEach((m) => {
        const rowSev = (m.getAttribute("data-sev") || "other").toLowerCase();
        const showMember = showGroup && expanded && (wanted === "all" ? true : rowSev === wanted);
        m.style.display = showMember ? "" : "none";
        const detailRow = m.nextElementSibling;
        if (detailRow && detailRow.classList.contains("detailRow")) {
          detailRow.style.display = showMember ? "" : "none";
          detailRow.hidden = true;
        }
      });
    });
  }

  rows.forEach((r) => r.addEventListener("click", () => toggleAccordion(r)));

  grouping.groups.forEach((g) => {
    g.groupRow.addEventListener("click", () => {
      const open = g.groupRow.getAttribute("aria-expanded") === "true";
      // Close per-finding accordions when toggling groups (avoids odd open states).
      closeAllAccordions();
      g.groupRow.setAttribute("aria-expanded", open ? "false" : "true");
      // Re-apply current filter so the right members become visible.
      const active = filters ? filters.querySelector("button.pill--active[data-sev]") : null;
      applyFilter(active ? active.getAttribute("data-sev") : "all");
    });
  });

  if (filters) {
    filters.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-sev]");
      if (!btn) return;
      const sev = btn.getAttribute("data-sev");
      Array.from(filters.querySelectorAll("button[data-sev]")).forEach((b) => b.classList.remove("pill--active"));
      btn.classList.add("pill--active");
      applyFilter(sev);
    });
  }

  // Default
  applyFilter("all");

  function normalizeValidationLabelText(raw) {
    const v = String(raw || "").trim();
    const vl = v.toLowerCase();
    if (["yes", "y", "true", "confirmed"].includes(vl)) return "Yes";
    if (
      [
        "requires_manual_check",
        "requires manual check",
        "manual_check",
        "needs_manual_check",
        "needs manual review",
        "unknown",
        "unclear",
        // Legacy/unsupported values: prefer manual review rather than hard invalidation in UI.
        "no",
        "false",
        "",
      ].includes(vl)
    )
      return "Requires manual check";
    return "Requires manual check";
  }

  function normalizeValidationLabelsInDom() {
    const detailRows = Array.from(document.querySelectorAll("#findingsTable tbody tr.detailRow"));
    detailRows.forEach((dr) => {
      const kvs = Array.from(dr.querySelectorAll(".kv"));
      kvs.forEach((kv) => {
        const k = kv.querySelector(".k");
        if (!k) return;
        if ((k.textContent || "").trim().toLowerCase() !== "validation") return;
        const code = kv.querySelector(".v code");
        if (!code) return;
        code.textContent = normalizeValidationLabelText(code.textContent);
      });
    });
  }

  // In case older reports/templates contain legacy labels, normalize on the client too.
  normalizeValidationLabelsInDom();

  function setCompareOpen(open) {
    if (!compareModal) return;
    compareModal.hidden = !open;
    if (open && comparePrevSelect) comparePrevSelect.focus();
  }

  async function fetchJson(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }

  function setJsonModalOpen(open) {
    if (!jsonModal) return;
    jsonModal.hidden = !open;
    if (open) {
      try {
        const pre = jsonModalPre;
        if (pre) pre.scrollTop = 0;
      } catch {
        // ignore
      }
    }
  }

  async function openJsonModal() {
    if (!jsonModalPre) return;
    setJsonModalOpen(true);
    jsonModalPre.textContent = "Loading…";
    try {
      const obj = await fetchJson("/api/report");
      jsonModalPre.textContent = JSON.stringify(obj, null, 2);
    } catch (e) {
      jsonModalPre.textContent = `Failed to load JSON: ${String(e && e.message ? e.message : e)}`;
    }
  }

  async function copyJsonFromModal() {
    if (!jsonModalPre) return;
    const txt = jsonModalPre.textContent || "";
    if (!txt || txt === "Loading…") return;
    try {
      await navigator.clipboard.writeText(txt);
      if (jsonCopyBtn) {
        const prev = jsonCopyBtn.textContent;
        jsonCopyBtn.textContent = "Copied";
        window.setTimeout(() => (jsonCopyBtn.textContent = prev), 900);
      }
    } catch {
      // ignore
    }
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, (ch) => {
      const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
      return map[ch] || ch;
    });
  }

  function toKey(f) {
    const file = (f.file || "").toLowerCase();
    const line = f.line != null ? String(f.line) : "";
    const title = (f.title || "").toLowerCase();
    return `${title}@@${file}:${line}`.trim();
  }

  function renderCompareCards(current, previous) {
    if (!compareGrid) return;
    const curFindings = Array.isArray(current && current.findings) ? current.findings : [];
    const prevFindings = Array.isArray(previous && previous.findings) ? previous.findings : [];

    const prevById = new Map(prevFindings.map((f) => [String(f.id || ""), f]));
    const prevByKey = new Map(prevFindings.map((f) => [toKey(f), f]));

    const cards = [];
    let changed = 0;
    curFindings.forEach((f) => {
      const id = String(f.id || "");
      const prev = (id && prevById.get(id)) || prevByKey.get(toKey(f)) || null;
      const curVs = normalizeValidationLabelText(f.validation_status);
      const prevVs = normalizeValidationLabelText(prev && prev.validation_status);
      const curVc = typeof f.validation_confidence === "number" ? f.validation_confidence : null;
      const prevVc = prev && typeof prev.validation_confidence === "number" ? prev.validation_confidence : null;
      const delta = curVc != null && prevVc != null ? curVc - prevVc : null;
      const sev = f.severity || "Unspecified";
      const loc = `${f.file || "—"}${f.line != null ? ":" + f.line : ""}`;

      const isDiff =
        (prev && (curVs !== prevVs || (curVc != null && prevVc != null && Math.abs(delta) >= 0.01) || String(sev) !== String(prev.severity))) ||
        false;
      if (isDiff) changed += 1;

      const deltaHtml =
        delta == null
          ? `<div class="compareDelta muted">Δ confidence: —</div>`
          : `<div class="compareDelta ${delta >= 0 ? "deltaUp" : "deltaDown"}">Δ confidence: ${delta >= 0 ? "+" : ""}${delta.toFixed(
              2
            )}</div>`;

      cards.push(`
        <div class="compareCard">
          <div class="compareCard__title">${esc(id)} — ${esc(f.title || "—")}</div>
          <div class="compareKV">
            <div><span class="k">Location</span> <code>${esc(loc)}</code></div>
            <div><span class="k">Severity</span> <code>${esc(sev)}</code>${prev ? ` <span class="muted">←</span> <code>${esc(prev.severity || "—")}</code>` : ""}</div>
            <div><span class="k">Validation</span> <code>${esc(curVs)}</code>${prev ? ` <span class="muted">←</span> <code>${esc(prevVs)}</code>` : ""}</div>
            <div><span class="k">Confidence</span> <code>${curVc == null ? "—" : curVc.toFixed(2)}</code>${
              prev ? ` <span class="muted">←</span> <code>${prevVc == null ? "—" : prevVc.toFixed(2)}</code>` : ""
            }</div>
          </div>
          ${deltaHtml}
        </div>
      `);
    });

    compareGrid.innerHTML = cards.join("") || `<div class="muted">No findings to compare.</div>`;
    if (compareMeta) {
      compareMeta.textContent = `Compared ${curFindings.length} current findings against ${prevFindings.length} previous findings. Changed: ${changed}.`;
    }
  }

  async function loadCompareOptions() {
    if (!comparePrevSelect) return;
    comparePrevSelect.innerHTML = `<option value="">Loading…</option>`;
    try {
      const data = await fetchJson("/api/reports");
      const currentPath = meta && meta.report_path ? String(meta.report_path) : "";
      const reports = Array.isArray(data && data.reports) ? data.reports : [];
      const options = reports
        .filter((r) => r && r.path && String(r.path) !== currentPath)
        .map((r) => `<option value="${esc(r.path)}">${esc(r.label || r.name || r.path)}</option>`);
      comparePrevSelect.innerHTML = options.join("") || `<option value="">No previous reports found</option>`;
    } catch {
      comparePrevSelect.innerHTML = `<option value="">Failed to load reports</option>`;
    }
  }

  async function runCompare() {
    if (!comparePrevSelect) return;
    const prevPath = String(comparePrevSelect.value || "");
    if (!prevPath) return;
    if (compareRunBtn) compareRunBtn.textContent = "Comparing…";
    try {
      const prev = await fetchJson(`/api/report_by_path?path=${encodeURIComponent(prevPath)}`);
      renderCompareCards(report, prev);
    } catch {
      if (compareGrid) compareGrid.innerHTML = `<div class="muted">Failed to load previous report.</div>`;
    } finally {
      if (compareRunBtn) compareRunBtn.textContent = "Compare";
    }
  }

  if (compareReportsBtn) {
    compareReportsBtn.addEventListener("click", async () => {
      setCompareOpen(true);
      await loadCompareOptions();
      // Auto-compare against the most recent available previous report.
      if (comparePrevSelect) {
        const first = Array.from(comparePrevSelect.options).find((o) => String(o.value || "").trim());
        if (first) {
          comparePrevSelect.value = first.value;
          await runCompare();
        }
      }
    });
  }
  if (compareCloseBtn) compareCloseBtn.addEventListener("click", () => setCompareOpen(false));
  if (compareModal) {
    const overlay = compareModal.querySelector(".modal__overlay");
    if (overlay) overlay.addEventListener("click", () => setCompareOpen(false));
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !compareModal.hidden) setCompareOpen(false);
    });
  }

  // JSON modal wiring
  if (viewJsonLink) {
    viewJsonLink.addEventListener("click", (e) => {
      e.preventDefault();
      openJsonModal();
    });
  }
  if (jsonCloseBtn) jsonCloseBtn.addEventListener("click", () => setJsonModalOpen(false));
  if (jsonCopyBtn) jsonCopyBtn.addEventListener("click", copyJsonFromModal);
  if (jsonModal) {
    const overlay = jsonModal.querySelector(".modal__overlay");
    if (overlay) overlay.addEventListener("click", () => setJsonModalOpen(false));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !jsonModal.hidden) setJsonModalOpen(false);
    });
  }
  if (compareRunBtn) compareRunBtn.addEventListener("click", runCompare);

  if (refreshDashboardBtn) {
    refreshDashboardBtn.addEventListener("click", () => {
      // Reload with cache-busting query param so the latest report + templates are fetched.
      const url = new URL(window.location.href);
      url.searchParams.set("_t", String(Date.now()));
      window.location.href = url.toString();
    });
  }

  function setChatOpen(open) {
    if (!chatWidget) return;
    const isOpen = open ? "true" : "false";
    chatWidget.setAttribute("data-open", isOpen);
    if (chatToggle) {
      chatToggle.setAttribute("aria-expanded", open ? "true" : "false");
      chatToggle.setAttribute("title", open ? "Close report assistant" : "Open report assistant");
      chatToggle.setAttribute("aria-label", open ? "Close report assistant" : "Open report assistant");
    }
    try {
      localStorage.setItem("dashboard_chat_open", isOpen);
    } catch {
      // ignore
    }
    if (open && chatInput) {
      // Focus input when opening.
      chatInput.focus();
    }
  }

  if (chatWidget) {
    let initialOpen = false;
    try {
      initialOpen = localStorage.getItem("dashboard_chat_open") === "true";
    } catch {
      initialOpen = false;
    }
    setChatOpen(initialOpen);
  }

  if (chatToggle) {
    chatToggle.addEventListener("click", () => setChatOpen(true));
  }
  if (chatClose) {
    chatClose.addEventListener("click", () => setChatOpen(false));
  }

  function fmtTime(ts) {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      if (Number.isNaN(d.getTime())) return String(ts);
      return d.toLocaleString();
    } catch {
      return String(ts);
    }
  }

  async function pollWorkflowStatus() {
    if (!workflowStatus) return;
    try {
      const res = await fetch("/api/status", { cache: "no-store" });
      if (!res.ok) throw new Error(`status ${res.status}`);
      const st = await res.json();
      const state = st && st.state ? String(st.state) : "idle";
      const stage = st && st.stage ? String(st.stage) : "Idle";
      const runId = st && st.run_id ? String(st.run_id) : "";
      const pct = st && typeof st.progress === "number" ? Math.max(0, Math.min(100, st.progress)) : 0;
      const msg = st && st.message ? String(st.message) : "";
      const updated = fmtTime(st && st.updated_at);
      const started = fmtTime(st && st.started_at);

      workflowStatus.hidden = false;
      workflowStatus.dataset.state = state;
      if (workflowPct) workflowPct.textContent = `${pct}%`;

      const metaParts = [];
      if (started) metaParts.push(`Started: ${started}`);
      if (updated) metaParts.push(`Updated: ${updated}`);
      if (workflowMeta) workflowMeta.textContent = metaParts.join(" • ");

      if (workflowError) {
        if (state === "error") {
          workflowError.hidden = false;
          workflowError.textContent = msg || "Pipeline failed. See terminal output for details.";
        } else {
          workflowError.hidden = true;
          workflowError.textContent = "";
        }
      }

      if (runPipelineBtn) {
        const running = state === "running";
        runPipelineBtn.disabled = running;
        runPipelineBtn.textContent = running ? "Running…" : "Run scan";
      }
      if (stopPipelineBtn) {
        const running = state === "running";
        stopPipelineBtn.disabled = !running;
        stopPipelineBtn.textContent = running ? "Stop" : "Stopped";
      }

      // Update 4-stage boxes.
      const stageL = stage.toLowerCase();
      let active = "repo";
      if (stageL.includes("skill") || stageL.includes("plan")) active = "plan";
      else if (stageL.includes("analy")) active = "analyze";
      else if (stageL.includes("eval") || stageL.includes("judge") || stageL.includes("verif")) active = "eval";
      else if (stageL.includes("complete") || state === "done") active = "eval";

      const order = ["repo", "plan", "analyze", "eval"];
      const activeIdx = order.indexOf(active);

      const stepRanges = {
        repo: [0, 25],
        plan: [25, 50],
        analyze: [50, 85],
        eval: [85, 100],
      };

      function clampPct(n) {
        const v = typeof n === "number" ? n : 0;
        return Math.max(0, Math.min(100, Math.round(v)));
      }

      function pctWithinRange(overall, start, end) {
        const span = Math.max(1, end - start);
        const t = (overall - start) / span;
        return clampPct(t * 100);
      }

      workflowSteps.forEach((el) => {
        const key = el.getAttribute("data-step");
        const idx = order.indexOf(key);

        // Ensure title stays consistent and single-sourced from the template.
        const baseTitle = (el.dataset && el.dataset.baseTitle) || "";
        if (baseTitle) {
          const titleEl = el.querySelector(".workflowStep__title");
          if (titleEl) titleEl.textContent = baseTitle;
        }

        let status = "pending";
        if (state === "done") status = "done";
        else if (state === "error") {
          if (idx < activeIdx) status = "done";
          else if (idx === activeIdx) status = "failed";
          else status = "pending";
        }
        else if (idx < activeIdx) status = "done";
        else if (idx === activeIdx) status = "active";
        else status = "pending";
        el.setAttribute("data-status", status);

        const badge = el.querySelector(".workflowStep__status");
        if (badge) {
          if (status === "done") {
            badge.textContent = "Done";
          } else if (status === "failed") {
            badge.textContent = "Failed";
          } else if (status === "active") {
            badge.innerHTML =
              'Running <span class="workflowDots" aria-hidden="true"><span>.</span><span>.</span><span>.</span></span>';
          } else {
            badge.textContent = "Pending";
          }
        }

        // Per-step progress: steps behind active are full, ahead are empty,
        // active step uses the overall progress mapped onto its range.
        let stepPct = 0;
        if (state === "done") {
          stepPct = 100;
        } else if (idx < activeIdx) {
          stepPct = 100;
        } else if (idx > activeIdx) {
          stepPct = 0;
        } else {
          const r = stepRanges[key] || [0, 100];
          stepPct = pctWithinRange(pct, r[0], r[1]);
          if (status === "active" && stepPct === 0 && state === "running") stepPct = 1;
        }
        stepPct = clampPct(stepPct);

        const pb = el.querySelector(".workflowStep__progress");
        if (pb) pb.setAttribute("aria-valuenow", String(stepPct));

        const pctEl = el.querySelector("[data-progress-pct]");
        if (pctEl) pctEl.textContent = `${stepPct}%`;
        else if (pb && !pb.querySelector) {
          // no-op: (defensive)
        } else {
          // Back-compat for older DOM where the progress container only contains text.
          try {
            if (pb && typeof pb.textContent === "string") pb.textContent = `${stepPct}%`;
          } catch {
            // ignore
          }
        }

        const fill = el.querySelector("[data-progress-fill]");
        if (fill) fill.style.width = `${stepPct}%`;
      });

      // Stop polling once the run is terminal.
      if ((state === "done" || state === "error") && workflowPollTimer) {
        window.clearInterval(workflowPollTimer);
        workflowPollTimer = null;
      }

      // If the run completed, refresh the dashboard once to load the latest report.
      // Use run_id to avoid infinite reload loops if the status remains "done".
      if (state === "done" && runId) {
        try {
          const key = "dashboard_last_refreshed_run_id";
          const last = sessionStorage.getItem(key) || "";
          if (last !== runId) {
            sessionStorage.setItem(key, runId);
            window.setTimeout(() => window.location.reload(), 250);
          }
        } catch {
          // If storage is unavailable, do nothing (avoid reload loops).
        }
      }
    } catch {
      // Keep UI quiet if status isn't available.
    }
  }

  // Poll workflow status in the background.
  if (workflowStatus) {
    pollWorkflowStatus();
    workflowPollTimer = window.setInterval(pollWorkflowStatus, 1000);
  }

  async function triggerPipelineRun() {
    if (!runPipelineBtn) return;
    runPipelineBtn.disabled = true;
    runPipelineBtn.textContent = "Starting…";
    try {
      const res = await fetch("/api/run", { method: "POST" });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `run failed: ${res.status}`);
      }
      // Immediately resume polling to reflect stage changes.
      if (!workflowPollTimer) {
        pollWorkflowStatus();
        workflowPollTimer = window.setInterval(pollWorkflowStatus, 1000);
      } else {
        pollWorkflowStatus();
      }
    } catch {
      runPipelineBtn.disabled = false;
      runPipelineBtn.textContent = "Run scan";
    }
  }

  if (runPipelineBtn) {
    runPipelineBtn.addEventListener("click", triggerPipelineRun);
  }

  async function stopCurrentRun() {
    if (!stopPipelineBtn) return;
    stopPipelineBtn.disabled = true;
    const prev = stopPipelineBtn.textContent;
    stopPipelineBtn.textContent = "Stopping…";
    try {
      const res = await fetch("/api/stop", { method: "POST" });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `stop failed: ${res.status}`);
      }
    } catch {
      // restore so the user can try again
      stopPipelineBtn.disabled = false;
      stopPipelineBtn.textContent = prev || "Stop";
      return;
    }
    // Force a refresh of the status immediately.
    pollWorkflowStatus();
  }

  if (stopPipelineBtn) {
    stopPipelineBtn.addEventListener("click", stopCurrentRun);
  }

  function appendChatMessage(role, text) {
    if (!chatLog) return;
    const msg = document.createElement("div");
    msg.className = `chatMsg ${role === "user" ? "chatMsg--user" : ""}`;
    const meta = document.createElement("div");
    meta.className = "chatMsg__meta";
    meta.textContent = role === "user" ? "You" : "Assistant";
    const body = document.createElement("div");
    body.className = "chatMsg__body";
    body.textContent = text || "";
    msg.appendChild(meta);
    msg.appendChild(body);
    chatLog.appendChild(msg);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  async function sendChat(message) {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, context: { last_matched_finding_id: window.__CHAT_LAST_FINDING_ID__ || null } }),
    });
    if (!res.ok) {
      throw new Error(`chat request failed: ${res.status}`);
    }
    return await res.json();
  }

  if (chatLog) {
    appendChatMessage(
      "assistant",
      "Ask me about the report. Try: `list findings` or `explain unsafe-string-function`."
    );
  }

  if (chatForm && chatInput) {
    chatForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const message = (chatInput.value || "").trim();
      if (!message) return;
      chatInput.value = "";
      appendChatMessage("user", message);
      appendChatMessage("assistant", "…");
      const pending = chatLog ? chatLog.lastElementChild : null;
      try {
        const data = await sendChat(message);
        try {
          if (data && data.matched_finding_id) window.__CHAT_LAST_FINDING_ID__ = String(data.matched_finding_id);
        } catch {
          // ignore
        }
        if (pending && pending.querySelector) {
          const body = pending.querySelector(".chatMsg__body");
          if (body) body.textContent = data.answer || "";
        } else {
          appendChatMessage("assistant", data.answer || "");
        }
      } catch (err) {
        const msg = err && err.message ? err.message : "Unknown error";
        if (pending && pending.querySelector) {
          const body = pending.querySelector(".chatMsg__body");
          if (body) body.textContent = `Error: ${msg}`;
        } else {
          appendChatMessage("assistant", `Error: ${msg}`);
        }
      }
    });
  }

  const filetypeBtn = document.getElementById("filetypeInfoBtn");
  const filetypePanel = document.getElementById("filetypeBreakdown");
  if (filetypeBtn && filetypePanel) {
    function syncFiletypeBtnLabel() {
      const open = filetypeBtn.getAttribute("aria-expanded") === "true";
      filetypeBtn.textContent = open ? "Hide breakdown" : "View breakdown";
      filetypeBtn.setAttribute("title", open ? "Hide breakdown" : "View breakdown");
    }

    syncFiletypeBtnLabel();
    filetypeBtn.addEventListener("click", () => {
      const open = filetypeBtn.getAttribute("aria-expanded") === "true";
      filetypeBtn.setAttribute("aria-expanded", open ? "false" : "true");
      filetypePanel.hidden = open;
      syncFiletypeBtnLabel();
    });
  }
})();

