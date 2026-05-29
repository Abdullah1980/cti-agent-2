let currentAnalysis = null;
let activeTab = "executive";
let currentLang = localStorage.getItem("cti_lang") || "ar";
let selectedCaseId = null;
let currentCases = [];
let currentHistory = [];
let currentCaseDetail = null;
const validViews = new Set(["dashboard", "results", "mitre", "cases", "history", "raw"]);
let activeView = validViews.has(location.hash.replace("#", "")) ? location.hash.replace("#", "") : "dashboard";
let activeRaw = "analysis";

const $ = (id) => document.getElementById(id);

const i18n = {
  ar: {
    eyebrow: "منصة استخبارات التهديدات",
    heroText: "تحليل مؤشرات الاختراق وربطها بـ MITRE ATT&CK مع تقارير تنفيذية وتشغيلية وتقنية.",
    checking: "فحص الإعدادات...",
    inputTitle: "إدخال المؤشرات",
    sample: "مثال",
    company: "اسم الشركة",
    indicators: "المؤشرات IOC",
    context: "سياق إضافي",
    useOpenAI: "استخدام OpenAI للتلخيص",
    analyze: "بدء التحليل",
    totalIndicators: "المؤشرات الفريدة",
    avgRisk: "متوسط الخطورة",
    critical: "حرج",
    high: "عال",
    summaryTitle: "ملخص التقارير",
    downloadExcel: "تحميل Excel",
    executive: "تنفيذي",
    operations: "عمليات",
    technical: "تقني",
    emptySummary: "ستظهر الملخصات هنا بعد التحليل.",
    resultsTitle: "نتائج المؤشرات",
    ioc: "المؤشر",
    type: "النوع",
    severity: "الخطورة",
    confidence: "الثقة",
    sources: "المصادر",
    noResults: "لا توجد نتائج بعد.",
    mitreTitle: "أهم تقنيات MITRE",
    noData: "لا توجد بيانات بعد.",
    configured: "مفعّل",
    notConfigured: "المفاتيح غير مضبوطة بعد",
    noSummary: "لا يوجد ملخص.",
    noResultsShort: "لا توجد نتائج.",
    needIoc: "ضع مؤشر واحد على الأقل.",
    analyzing: "جاري التحليل وجلب نتائج المصادر...",
    failed: "تعذر إكمال التحليل.",
    done: "اكتمل التحليل. يمكنك تحميل ملف Excel الآن.",
    unexpected: "حدث خطأ غير متوقع.",
    healthFailed: "تعذر فحص الإعدادات",
    companyDefault: "الشركة",
    indicatorsPlaceholder: "ضع IP أو Domain أو URL أو Hash. يدعم hxxp و[.] وإزالة التكرار تلقائيًا.",
    contextPlaceholder: "مثال: بيئة مالية، أصول حساسة، حملة تصيد مستهدفة...",
    sampleContext: "تحليل أولي لمؤشرات وصلت من بلاغ تصيد.",
    submitted: "مدخل",
    deduped: "مكرر أزيل",
    labels: "وسوم",
    agreement: "اتفاق المصادر",
    caseCreated: "الحالة",
    casesTitle: "إدارة الحالات",
    refreshCases: "تحديث",
    noCases: "لا توجد حالات مؤتمتة بعد.",
    selectCase: "اختر حالة لعرض التفاصيل.",
    caseStatus: "الحالة",
    casePriority: "الأولوية",
    caseCategory: "التصنيف",
    caseReason: "سبب فتح الحالة",
    caseAnalyses: "التحليلات المرتبطة",
    caseIndicators: "أهم المؤشرات",
    caseUpdated: "آخر تحديث",
    caseCounts: "تحليلات / مؤشرات",
    casesLoadFailed: "تعذر تحميل الحالات.",
    saveCase: "حفظ الحالة",
    caseNotes: "ملاحظات المحلل",
    caseChecklist: "قائمة الإجراءات",
    caseTimeline: "سجل الحالة",
    caseSaved: "تم حفظ تحديثات الحالة.",
    caseSaveFailed: "تعذر حفظ الحالة.",
    statusOpen: "Open",
    statusInProgress: "In Progress",
    statusContainment: "Containment",
    statusClosed: "Closed",
    navDashboard: "لوحة القيادة",
    navResults: "النتائج",
    navMitre: "MITRE",
    navCases: "الحالات",
    navHistory: "السجل",
    navRaw: "البيانات الخام",
    historyTitle: "سجل التحليلات",
    refreshHistory: "تحديث",
    historyEmpty: "لا توجد تحليلات سابقة بعد.",
    openAnalysis: "فتح التحليل",
    historyLoadFailed: "تعذر تحميل سجل التحليلات.",
    analysisLoaded: "تم فتح التحليل السابق داخل لوحة القيادة.",
    downloadCaseReport: "تحميل تقرير الحالة",
    rawTitle: "البيانات الخام",
    copyRaw: "نسخ",
    rawAnalysis: "التحليل الحالي",
    rawCases: "الحالات",
    rawCaseDetail: "الحالة المختارة",
    rawHistory: "السجل",
    rawEmpty: "شغل تحليل أو اختر حالة لعرض JSON هنا.",
    copied: "تم نسخ البيانات الخام.",
    nothingToCopy: "لا توجد بيانات لنسخها.",
  },
  en: {
    eyebrow: "Cyber Threat Intelligence Platform",
    heroText: "IOC triage, MITRE ATT&CK mapping, and executive, operations, and technical reporting.",
    checking: "Checking configuration...",
    inputTitle: "Indicator Intake",
    sample: "Sample",
    company: "Company name",
    indicators: "IOCs",
    context: "Additional context",
    useOpenAI: "Use OpenAI summaries",
    analyze: "Analyze",
    totalIndicators: "Unique indicators",
    avgRisk: "Average risk",
    critical: "Critical",
    high: "High",
    summaryTitle: "Report Summaries",
    downloadExcel: "Download Excel",
    executive: "Executive",
    operations: "Operations",
    technical: "Technical",
    emptySummary: "Summaries will appear here after analysis.",
    resultsTitle: "Indicator Results",
    ioc: "Indicator",
    type: "Type",
    severity: "Severity",
    confidence: "Confidence",
    sources: "Sources",
    noResults: "No results yet.",
    mitreTitle: "Top MITRE Techniques",
    noData: "No data yet.",
    configured: "Enabled",
    notConfigured: "API keys are not configured yet",
    noSummary: "No summary available.",
    noResultsShort: "No results.",
    needIoc: "Enter at least one indicator.",
    analyzing: "Normalizing IOCs and querying sources...",
    failed: "Analysis could not be completed.",
    done: "Analysis completed. You can download the Excel report now.",
    unexpected: "Unexpected error.",
    healthFailed: "Could not check configuration",
    companyDefault: "Company",
    indicatorsPlaceholder: "Enter IP, domain, URL, or hash. Supports hxxp, [.] and automatic deduplication.",
    contextPlaceholder: "Example: financial environment, sensitive assets, targeted phishing campaign...",
    sampleContext: "Initial triage for indicators reported from a phishing alert.",
    submitted: "submitted",
    deduped: "duplicates removed",
    labels: "Labels",
    agreement: "Source agreement",
    caseCreated: "Case",
    casesTitle: "Case Management",
    refreshCases: "Refresh",
    noCases: "No automated cases yet.",
    selectCase: "Select a case to view details.",
    caseStatus: "Status",
    casePriority: "Priority",
    caseCategory: "Category",
    caseReason: "Case rationale",
    caseAnalyses: "Linked analyses",
    caseIndicators: "Top indicators",
    caseUpdated: "Last updated",
    caseCounts: "Analyses / Indicators",
    casesLoadFailed: "Could not load cases.",
    saveCase: "Save Case",
    caseNotes: "Analyst notes",
    caseChecklist: "Action checklist",
    caseTimeline: "Timeline",
    caseSaved: "Case updates saved.",
    caseSaveFailed: "Could not save case.",
    statusOpen: "Open",
    statusInProgress: "In Progress",
    statusContainment: "Containment",
    statusClosed: "Closed",
    navDashboard: "Dashboard",
    navResults: "Results",
    navMitre: "MITRE",
    navCases: "Cases",
    navHistory: "History",
    navRaw: "Raw Data",
    historyTitle: "Analysis History",
    refreshHistory: "Refresh",
    historyEmpty: "No previous analyses yet.",
    openAnalysis: "Open Analysis",
    historyLoadFailed: "Could not load analysis history.",
    analysisLoaded: "Previous analysis loaded into the dashboard.",
    downloadCaseReport: "Download Case Report",
    rawTitle: "Raw Data",
    copyRaw: "Copy",
    rawAnalysis: "Current analysis",
    rawCases: "Cases",
    rawCaseDetail: "Selected case",
    rawHistory: "History",
    rawEmpty: "Run an analysis or select a case to view raw JSON here.",
    copied: "Raw data copied.",
    nothingToCopy: "No raw data to copy.",
  },
};

const t = (key) => i18n[currentLang][key] || i18n.en[key] || key;

function setMessage(text) {
  $("message").textContent = text;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function applyLanguage(lang) {
  currentLang = lang;
  localStorage.setItem("cti_lang", lang);
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  $("langAr").classList.toggle("active", lang === "ar");
  $("langEn").classList.toggle("active", lang === "en");
  $("companyName").placeholder = t("companyDefault");
  if (!$("companyName").value || ["الشركة", "Company"].includes($("companyName").value)) {
    $("companyName").value = t("companyDefault");
  }
  $("indicators").placeholder = t("indicatorsPlaceholder");
  $("context").placeholder = t("contextPlaceholder");
  if (!currentAnalysis) {
    $("summaryText").textContent = t("emptySummary");
    $("resultsBody").innerHTML = `<tr><td colspan="6" class="empty">${t("noResults")}</td></tr>`;
    $("mitreList").textContent = t("noData");
  } else {
    renderMetrics(currentAnalysis.stats);
    renderResults(currentAnalysis.indicators);
    updateSummary();
  }
  renderRawData();
  loadHealth().catch(() => {
    $("status").textContent = t("healthFailed");
  });
  loadCases(selectedCaseId).catch(() => {
    const list = $("casesList");
    if (list) list.textContent = t("casesLoadFailed");
  });
}

function switchView(view, pushState = true) {
  if (!validViews.has(view)) view = "dashboard";
  activeView = view;
  document.querySelectorAll(".view-page").forEach((section) => {
    section.classList.toggle("hidden", section.dataset.view !== view);
  });
  document.querySelectorAll(".page-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.viewTarget === view);
  });
  if (pushState && location.hash.replace("#", "") !== view) {
    history.pushState(null, "", `#${view}`);
  }
  if (view === "cases") {
    loadCases(selectedCaseId).catch(() => setMessage(t("casesLoadFailed")));
  }
  if (view === "history") {
    loadHistory().catch(() => setMessage(t("historyLoadFailed")));
  }
  if (view === "raw") {
    renderRawData();
  }
}

function switchRaw(target) {
  activeRaw = target;
  document.querySelectorAll(".raw-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.rawTarget === target);
  });
  renderRawData();
}

function rawPayload() {
  if (activeRaw === "analysis") return currentAnalysis;
  if (activeRaw === "caseDetail") return currentCaseDetail;
  if (activeRaw === "cases") return currentCases;
  if (activeRaw === "history") return currentHistory;
  return currentHistory;
}

function renderRawData() {
  const raw = $("rawData");
  if (!raw) return;
  const payload = rawPayload();
  if (!payload || (Array.isArray(payload) && !payload.length)) {
    raw.textContent = t("rawEmpty");
    return;
  }
  raw.textContent = JSON.stringify(payload, null, 2);
}

async function loadHealth() {
  const res = await fetch("/api/health");
  const data = await res.json();
  const ready = [
    data.openai && "OpenAI",
    data.virustotal && "VirusTotal",
    data.malwarebazaar && "MalwareBazaar",
    data.abuseipdb && "AbuseIPDB",
    data.urlscan && "URLScan",
    data.otx && "OTX",
  ].filter(Boolean);
  $("status").textContent = ready.length ? `${t("configured")}: ${ready.join(", ")}` : t("notConfigured");
}

function updateSummary() {
  if (!currentAnalysis) return;
  $("summaryText").textContent = currentAnalysis.summaries[activeTab] || t("noSummary");
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === activeTab);
  });
}

function renderMetrics(stats) {
  $("total").textContent = stats.total ?? 0;
  $("avg").textContent = stats.average_score ?? 0;
  $("critical").textContent = stats.by_severity?.Critical ?? 0;
  $("high").textContent = stats.by_severity?.High ?? 0;
  const submitted = stats.submitted_count ?? stats.total ?? 0;
  const deduped = stats.deduplicated_count ?? 0;
  setMessage(currentAnalysis ? `${submitted} ${t("submitted")} | ${deduped} ${t("deduped")}` : "");
}

function renderCaseBanner(caseInfo) {
  const banner = $("caseBanner");
  if (!banner) return;
  if (!caseInfo || (!caseInfo.id && caseInfo.status === "No Case")) {
    banner.classList.remove("hidden");
    banner.innerHTML = `<strong>${t("caseCreated")}:</strong> No automatic case created. <span>${escapeHtml(caseInfo?.reason || "")}</span>`;
    return;
  }
  banner.classList.remove("hidden");
  const name = caseInfo.name || caseInfo.id || "Case";
  banner.innerHTML = `
    <strong>${t("caseCreated")}:</strong>
    ${escapeHtml(name)}
    <span>${escapeHtml(caseInfo.priority || "")} | ${escapeHtml(caseInfo.category || "")} | ${escapeHtml(caseInfo.linked_by || "")}</span>
  `;
}

function agreementText(agreement = {}) {
  const unavailable = agreement.source_unavailable ? ` U:${agreement.source_unavailable}` : "";
  return `M:${agreement.malicious ?? 0} S:${agreement.suspicious ?? 0} C:${agreement.clean ?? 0}${unavailable}`;
}

function renderResults(indicators) {
  const body = $("resultsBody");
  if (!indicators.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${t("noResultsShort")}</td></tr>`;
    return;
  }
  body.innerHTML = indicators.map((item) => {
    const sources = item.verdicts.map((v) => `${v.source}: ${v.status}<br><small>${escapeHtml(v.summary)}</small>`).join("<hr>");
    const mitre = item.mitre.map((m) => `${m.technique_id} - ${escapeHtml(m.technique)}<br><small>${escapeHtml(m.tactic)}</small>`).join("<hr>");
    const labels = (item.threat_labels || []).map((label) => `<span class="tag">${escapeHtml(label)}</span>`).join(" ");
    const originals = (item.normalized_from || []).filter((v) => v !== item.value).slice(0, 3).join(", ");
    return `
      <tr>
        <td>
          <strong>${escapeHtml(item.value)}</strong>
          <small>${item.occurrence_count > 1 ? `x${item.occurrence_count}` : ""}</small>
          ${originals ? `<br><small>from: ${escapeHtml(originals)}</small>` : ""}
          ${labels ? `<div class="tags">${labels}</div>` : ""}
        </td>
        <td>${escapeHtml(item.type)}</td>
        <td><span class="badge ${item.severity}">${item.severity}</span><br>${item.risk_score}/100</td>
        <td><span class="badge confidence-${item.confidence}">${item.confidence}</span><br><small>${t("agreement")}: ${agreementText(item.source_agreement)}</small></td>
        <td>${sources}</td>
        <td>${mitre}</td>
      </tr>
    `;
  }).join("");
}

function renderMitre(stats) {
  const entries = Object.entries(stats.mitre || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    $("mitreList").className = "mitre-list empty";
    $("mitreList").textContent = t("noData");
    return;
  }
  $("mitreList").className = "mitre-list";
  $("mitreList").innerHTML = entries.map(([name, count]) => `
    <div class="mitre-item">
      <strong>${escapeHtml(name)}</strong>
      <span>${count}</span>
    </div>
  `).join("");
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(`${value}Z`);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(currentLang === "ar" ? "ar-SA" : "en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

async function loadCases(preferredId = null) {
  const list = $("casesList");
  const detail = $("caseDetail");
  if (!list || !detail) return;

  const res = await fetch("/api/cases");
  if (!res.ok) throw new Error(t("casesLoadFailed"));
  const cases = await res.json();
  currentCases = cases;
  renderRawData();

  if (!cases.length) {
    selectedCaseId = null;
    currentCaseDetail = null;
    list.className = "cases-list empty";
    list.textContent = t("noCases");
    detail.className = "case-detail empty";
    detail.textContent = t("selectCase");
    renderRawData();
    return;
  }

  selectedCaseId = preferredId || selectedCaseId || cases[0].id;
  if (!cases.some((item) => item.id === selectedCaseId)) selectedCaseId = cases[0].id;
  renderCaseList(cases);
  await loadCaseDetail(selectedCaseId);
}

async function loadHistory() {
  const list = $("historyList");
  if (!list) return;
  const res = await fetch("/api/analyses");
  if (!res.ok) throw new Error(t("historyLoadFailed"));
  const rows = await res.json();
  currentHistory = rows;
  renderRawData();
  if (!rows.length) {
    list.className = "history-list empty";
    list.textContent = t("historyEmpty");
    return;
  }
  list.className = "history-list";
  list.innerHTML = rows.map((item) => `
    <article class="history-card">
      <div>
        <strong>${escapeHtml(item.company_name || "Company")}</strong>
        <span>${formatDate(item.created_at)}</span>
      </div>
      <div class="history-meta">
        <span>ID: ${escapeHtml(item.id)}</span>
        <span>${t("totalIndicators")}: ${escapeHtml(item.total)}</span>
        <span>${t("avgRisk")}: ${escapeHtml(item.average_score)}</span>
        <span>${escapeHtml(item.language || "")}</span>
      </div>
      <div class="history-actions">
        <button type="button" data-open-analysis="${escapeHtml(item.id)}">${t("openAnalysis")}</button>
        <a class="download slim" href="/api/analyses/${encodeURIComponent(item.id)}/excel">${t("downloadExcel")}</a>
      </div>
    </article>
  `).join("");
  list.querySelectorAll("[data-open-analysis]").forEach((button) => {
    button.addEventListener("click", async () => openAnalysis(button.dataset.openAnalysis));
  });
}

async function openAnalysis(analysisId) {
  const res = await fetch(`/api/analyses/${encodeURIComponent(analysisId)}`);
  if (!res.ok) throw new Error(t("failed"));
  currentAnalysis = await res.json();
  renderMetrics(currentAnalysis.stats);
  renderCaseBanner(currentAnalysis.case);
  renderResults(currentAnalysis.indicators || []);
  renderMitre(currentAnalysis.stats || {});
  activeTab = "executive";
  updateSummary();
  $("excelLink").href = `/api/analyses/${currentAnalysis.id}/excel`;
  $("excelLink").classList.remove("disabled");
  renderRawData();
  if (currentAnalysis.case?.id) {
    await loadCases(currentAnalysis.case.id);
  }
  switchView("dashboard");
  setMessage(t("analysisLoaded"));
}

function renderCaseList(cases) {
  const list = $("casesList");
  list.className = "cases-list";
  list.innerHTML = cases.map((item) => `
    <button class="case-card ${item.id === selectedCaseId ? "active" : ""}" type="button" data-case-id="${escapeHtml(item.id)}">
      <span class="case-card-title">${escapeHtml(item.name)}</span>
      <span class="case-card-meta">
        <span class="badge priority-${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span>
        <span>${escapeHtml(item.status)}</span>
        <span>${escapeHtml(item.category)}</span>
      </span>
      <span class="case-card-foot">
        <span>${t("caseCounts")}: ${item.analysis_count ?? 0} / ${item.indicator_count ?? 0}</span>
        <span>${formatDate(item.updated_at)}</span>
      </span>
    </button>
  `).join("");

  list.querySelectorAll("[data-case-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      selectedCaseId = button.dataset.caseId;
      renderCaseList(cases);
      await loadCaseDetail(selectedCaseId);
    });
  });
}

async function loadCaseDetail(caseId) {
  const detail = $("caseDetail");
  const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`);
  if (!res.ok) throw new Error(t("casesLoadFailed"));
  const item = await res.json();
  currentCaseDetail = item;
  renderCaseDetail(item);
  renderRawData();
}

function renderCaseDetail(item) {
  const detail = $("caseDetail");
  const analyses = item.analyses || [];
  const indicators = item.indicators || [];
  const tasks = item.tasks || [];
  const timeline = item.timeline || [];
  detail.className = "case-detail";
  detail.innerHTML = `
    <div class="case-detail-head">
      <div>
        <h3>${escapeHtml(item.name)}</h3>
        <p>${escapeHtml(item.id)}</p>
      </div>
      <div class="case-head-actions">
        <span class="badge priority-${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span>
        <a class="download slim" href="/api/cases/${encodeURIComponent(item.id)}/excel">${t("downloadCaseReport")}</a>
      </div>
    </div>
    <div class="case-controls">
      <label>
        <span>${t("caseStatus")}</span>
        <select id="caseStatusSelect">
          ${["Open", "In Progress", "Containment", "Closed"].map((status) => `
            <option value="${status}" ${item.status === status ? "selected" : ""}>${escapeHtml(status)}</option>
          `).join("")}
        </select>
      </label>
      <button id="saveCaseBtn" class="primary compact" type="button">${t("saveCase")}</button>
    </div>
    <label class="case-notes">
      <span>${t("caseNotes")}</span>
      <textarea id="caseNotesInput" rows="4">${escapeHtml(item.notes || "")}</textarea>
    </label>
    <div class="case-kpis">
      <div><span>${t("caseStatus")}</span><strong>${escapeHtml(item.status)}</strong></div>
      <div><span>${t("caseCategory")}</span><strong>${escapeHtml(item.category)}</strong></div>
      <div><span>${t("caseUpdated")}</span><strong>${formatDate(item.updated_at)}</strong></div>
    </div>
    <section class="case-note">
      <h4>${t("caseReason")}</h4>
      <p>${escapeHtml(item.reason)}</p>
    </section>
    <section>
      <h4>${t("caseChecklist")}</h4>
      ${renderCaseTasks(tasks)}
    </section>
    <section>
      <h4>${t("caseAnalyses")}</h4>
      ${renderAnalysesTable(analyses)}
    </section>
    <section>
      <h4>${t("caseIndicators")}</h4>
      ${renderCaseIndicators(indicators)}
    </section>
    <section>
      <h4>${t("caseTimeline")}</h4>
      ${renderCaseTimeline(timeline)}
    </section>
  `;
  $("saveCaseBtn").addEventListener("click", saveCaseDetail);
}

function renderCaseTasks(tasks) {
  if (!tasks.length) return `<p class="empty">${t("noData")}</p>`;
  return `
    <div class="case-tasks">
      ${tasks.map((task) => `
        <label class="case-task">
          <input type="checkbox" data-task-id="${task.id}" ${task.completed ? "checked" : ""} />
          <span>${escapeHtml(task.title)}</span>
        </label>
      `).join("")}
    </div>
  `;
}

function renderCaseTimeline(timeline) {
  if (!timeline.length) return `<p class="empty">${t("noData")}</p>`;
  return `
    <div class="case-timeline">
      ${timeline.slice(0, 12).map((event) => `
        <div class="timeline-item">
          <strong>${escapeHtml(event.event_type)}</strong>
          <span>${formatDate(event.created_at)}</span>
          <p>${escapeHtml(event.message)}</p>
        </div>
      `).join("")}
    </div>
  `;
}

async function saveCaseDetail() {
  if (!currentCaseDetail?.id) return;
  const tasks = Array.from(document.querySelectorAll("[data-task-id]")).map((input) => ({
    id: Number(input.dataset.taskId),
    completed: input.checked,
  }));
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(currentCaseDetail.id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: $("caseStatusSelect").value,
        notes: $("caseNotesInput").value,
        tasks,
      }),
    });
    if (!res.ok) throw new Error(t("caseSaveFailed"));
    currentCaseDetail = await res.json();
    renderCaseDetail(currentCaseDetail);
    renderRawData();
    await loadCases(currentCaseDetail.id);
    setMessage(t("caseSaved"));
  } catch (err) {
    setMessage(err.message || t("caseSaveFailed"));
  }
}

function renderAnalysesTable(analyses) {
  if (!analyses.length) return `<p class="empty">${t("noData")}</p>`;
  return `
    <div class="mini-table-wrap">
      <table class="mini-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>${t("avgRisk")}</th>
            <th>${t("totalIndicators")}</th>
            <th>${t("critical")} / ${t("high")}</th>
            <th>${t("caseUpdated")}</th>
          </tr>
        </thead>
        <tbody>
          ${analyses.map((row) => `
            <tr>
              <td>${escapeHtml(row.id)}</td>
              <td>${row.average_score ?? 0}</td>
              <td>${row.total_iocs ?? 0}</td>
              <td>${row.high_critical ?? 0}</td>
              <td>${formatDate(row.created_at)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderCaseIndicators(indicators) {
  if (!indicators.length) return `<p class="empty">${t("noData")}</p>`;
  const top = indicators.slice(0, 12);
  return `
    <div class="case-indicators">
      ${top.map((ioc) => {
        const labels = safeJsonList(ioc.threat_labels).slice(0, 4).map((label) => `<span class="tag">${escapeHtml(label)}</span>`).join("");
        return `
          <div class="case-ioc">
            <strong>${escapeHtml(ioc.value)}</strong>
            <span>${escapeHtml(ioc.type)} | ${escapeHtml(ioc.confidence)} | ${ioc.risk_score}/100</span>
            <span class="badge ${escapeHtml(ioc.severity)}">${escapeHtml(ioc.severity)}</span>
            <div class="tags">${labels}</div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function safeJsonList(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function analyze() {
  const indicators = $("indicators").value.trim();
  if (!indicators) {
    setMessage(t("needIoc"));
    return;
  }
  $("analyzeBtn").disabled = true;
  setMessage(t("analyzing"));
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        company_name: $("companyName").value.trim() || t("companyDefault"),
        indicators,
        context: $("context").value.trim(),
        use_openai: $("useOpenAI").checked,
        language: currentLang,
      }),
    });
    if (!res.ok) throw new Error(t("failed"));
    currentAnalysis = await res.json();
    renderMetrics(currentAnalysis.stats);
    renderCaseBanner(currentAnalysis.case);
    renderResults(currentAnalysis.indicators);
    renderMitre(currentAnalysis.stats);
    activeTab = "executive";
    updateSummary();
    renderRawData();
    $("excelLink").href = `/api/analyses/${currentAnalysis.id}/excel`;
    $("excelLink").classList.remove("disabled");
    if (currentAnalysis.case?.id) {
      await loadCases(currentAnalysis.case.id);
    } else {
      await loadCases();
    }
    setMessage(t("done"));
  } catch (err) {
    setMessage(err.message || t("unexpected"));
  } finally {
    $("analyzeBtn").disabled = false;
  }
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    activeTab = btn.dataset.tab;
    updateSummary();
  });
});

document.querySelectorAll(".page-tab").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.viewTarget));
});

document.querySelectorAll(".raw-tab").forEach((btn) => {
  btn.addEventListener("click", () => switchRaw(btn.dataset.rawTarget));
});

$("sampleBtn").addEventListener("click", () => {
  $("companyName").value = currentLang === "ar" ? "شركة ACME" : "ACME";
  $("indicators").value = "hxxp://110.36.80.162:47289/bin.sh\n110.36.80.162:47289\nexample[.]com\nhttps://example.com/login\n44d88612fea8a8f36de82e1278abb02f";
  $("context").value = t("sampleContext");
});

$("langAr").addEventListener("click", () => applyLanguage("ar"));
$("langEn").addEventListener("click", () => applyLanguage("en"));
$("analyzeBtn").addEventListener("click", analyze);
$("refreshCasesBtn").addEventListener("click", () => loadCases(selectedCaseId).catch(() => setMessage(t("casesLoadFailed"))));
$("refreshHistoryBtn").addEventListener("click", () => loadHistory().catch(() => setMessage(t("historyLoadFailed"))));
$("copyRawBtn").addEventListener("click", async () => {
  const payload = rawPayload();
  if (!payload || (Array.isArray(payload) && !payload.length)) {
    setMessage(t("nothingToCopy"));
    return;
  }
  await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  setMessage(t("copied"));
});
window.addEventListener("hashchange", () => switchView(location.hash.replace("#", ""), false));
applyLanguage(currentLang);
switchView(activeView, false);
