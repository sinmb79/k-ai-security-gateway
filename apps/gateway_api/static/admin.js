const state = {
  events: [],
  policy: null,
  privacy: null,
  approvals: [],
  policySummary: null,
  simulationResult: null,
};

const $ = (selector) => document.querySelector(selector);
let adminToken = sessionStorage.getItem("kaiAdminToken") || "";

function syncAuthInput() {
  const input = $("#adminToken");
  if (input) {
    input.value = adminToken;
  }
}

function withAdminHeaders(headers = {}) {
  const nextHeaders = { ...headers };
  if (adminToken) {
    nextHeaders.Authorization = `Bearer ${adminToken}`;
  }
  return nextHeaders;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function actionBadge(action) {
  const safeAction = escapeHtml(action || "unknown");
  return `<span class="badge ${safeAction}">${safeAction}</span>`;
}

function shortId(value) {
  if (!value) return "-";
  return String(value).slice(0, 8);
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString("ko-KR", { hour12: false });
}

async function fetchJson(url, options = {}) {
  const { admin = false, headers = {}, ...fetchOptions } = options;
  if (admin && !adminToken) {
    throw new Error("admin token is required");
  }
  const response = await fetch(url, {
    ...fetchOptions,
    headers: admin ? withAdminHeaders(headers) : headers,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${text}`);
  }
  return response.json();
}

async function submitPrompt(prompt, dataGrade = "internal") {
  return fetchJson("/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "gateway-test",
      data_grade: dataGrade,
      model_zone: "external",
      messages: [{ role: "user", content: prompt }],
    }),
  });
}

async function submitPolicySimulation(payload) {
  return fetchJson("/v1/policies/simulate", {
    admin: true,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function fetchPolicies() {
  return fetchJson("/v1/policies", { admin: true });
}

async function refresh() {
  if (!adminToken) {
    render();
    $("#serverStatus").textContent = "관리 토큰이 필요합니다";
    return;
  }
  try {
    const [events, policyReport, privacy, approvals, policySummary] = await Promise.all([
      fetchJson("/v1/audit/events", { admin: true }),
      fetchJson("/v1/reports/policy", { admin: true }),
      fetchJson("/v1/reports/privacy-export", { admin: true }),
      fetchJson("/v1/approvals/pending", { admin: true }),
      fetchPolicies(),
    ]);
    state.events = events.reverse();
    state.policy = policyReport;
    state.privacy = privacy;
    state.approvals = approvals;
    state.policySummary = policySummary;
    render();
    $("#serverStatus").textContent = "API 연결됨";
  } catch (error) {
    $("#serverStatus").textContent = "API 연결 실패";
    console.error(error);
  }
}

async function handlePromptSubmit(event) {
  event.preventDefault();
  const prompt = $("#promptInput").value.trim();
  const dataGrade = $("#dataGrade").value;
  if (!prompt || !dataGrade) return;
  await submitPrompt(prompt, dataGrade);
  await refresh();
}

async function handlePolicySimulateSubmit(event) {
  event.preventDefault();
  if (!adminToken) return;
  const payload = {
    prompt: $("#simulatePrompt").value,
    data_grade: $("#simulateDataGrade").value,
    model_zone: $("#simulateModelZone").value,
    requested_model: $("#simulateModel").value || "gateway-model",
  };

  $("#simulateStatus").textContent = "실행 중...";
  try {
    const result = await submitPolicySimulation(payload);
    state.simulationResult = result;
    renderSimulation();
    $("#simulateStatus").textContent = "완료";
  } catch (error) {
    $("#simulateStatus").textContent = `실패: ${error.message}`;
    state.simulationResult = null;
    renderSimulation();
  }
}

function seedMask() {
  $("#promptInput").value = "연락처 010-1234-5678 는 마스킹 처리";
}

function seedApproval() {
  $("#promptInput").value = "API key와 secret 정보 전송 요청";
}

function render() {
  const policy = state.policy || {};
  const privacy = state.privacy || {};
  $("#lastUpdated").textContent = `마지막 갱신: ${new Date().toLocaleTimeString("ko-KR", {
    hour12: false,
  })}`;
  $("#requestCount").textContent = policy.request_count || 0;
  $("#blockedCount").textContent = policy.blocked || 0;
  $("#maskedCount").textContent = policy.masked || 0;
  $("#approvalCount").textContent = policy.requires_human_review || 0;
  $("#riskCount").textContent = policy.risk_event_count || 0;
  $("#eventCount").textContent = `${state.events.length}건`;
  $("#pendingCount").textContent = `${state.approvals.length}건`;
  $("#privacyMasked").textContent = privacy.masked_requests || 0;
  $("#privacyApproval").textContent = privacy.approval_required_requests || 0;
  $("#privacyBlocked").textContent = privacy.blocked_requests || 0;
  $("#privacyChanged").textContent = privacy.prompt_changes || 0;
  if (state.policySummary) {
    $("#policySummaryLabel").textContent = `버전: ${escapeHtml(state.policySummary.version)} | ${escapeHtml(state.policySummary.source)}`;
  } else {
    $("#policySummaryLabel").textContent = "요약 없음";
  }
  renderEvents();
  renderPolicies();
  renderApprovals();
  renderRouting();
  renderSimulation();
}

function renderEvents() {
  const rows = state.events.slice(0, 12).map((event) => {
    const action = event.payload?.action || event.payload?.status || "";
    const policyId = event.payload?.policy_id || event.payload?.approval_id || "-";
    return `<tr>
      <td>${formatTime(event.timestamp)}</td>
      <td>${escapeHtml(event.event_type)}</td>
      <td>${escapeHtml(shortId(event.request_id))}</td>
      <td>${action ? actionBadge(action) : ""} <span class="muted">${escapeHtml(policyId)}</span></td>
    </tr>`;
  });
  $("#eventRows").innerHTML = rows.join("") || `<tr><td colspan="4">이벤트가 없습니다.</td></tr>`;
}

function renderPolicies() {
  const policies = state.policySummary?.policies || [];
  $("#policyList").innerHTML =
    policies
      .map((policy) => {
        const when = Object.entries(policy.when || {})
          .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`)
          .join(", ");
        const route = policy.route_model_zone ? ` (${policy.route_model_zone})` : "";
        return `<li><span title="${escapeHtml(when)}">${escapeHtml(policy.id)}</span><strong>${actionBadge(policy.action)}${escapeHtml(route)}</strong></li>`;
      })
      .join("") || `<li><span>정의된 정책이 없습니다.</span><strong>0</strong></li>`;
}

function renderApprovals() {
  $("#approvalList").innerHTML =
    state.approvals
      .slice(0, 6)
      .map(
        (approval) => `<div class="approval-item">
          <strong>${escapeHtml(shortId(approval.approval_id))} / ${escapeHtml(approval.status)}</strong>
          <span>${escapeHtml(approval.reason)}</span>
          <span class="muted">요청 ${escapeHtml(shortId(approval.request_id))} / ${escapeHtml(approval.requested_by)}</span>
        </div>`
      )
      .join("") || `<div class="approval-item"><strong>대기 항목 없음</strong><span class="muted">표시할 항목이 없습니다.</span></div>`;
}

function renderRouting() {
  const routed = state.events
    .filter((event) => event.event_type === "policy_decided")
    .slice(0, 5)
    .map((event) => {
      const action = event.payload?.action || "unknown";
      return `<div class="routing-item">
        <strong>${actionBadge(action)} ${escapeHtml(event.payload?.policy_id || "")}</strong>
        <span class="muted">요청 ${escapeHtml(shortId(event.request_id))} / ${event.payload?.effective_prompt_changed ? "변경됨" : "변경 없음"}</span>
      </div>`;
    });
  $("#routingList").innerHTML =
    routed.join("") || `<div class="routing-item"><strong>정책 결정 기록 없음</strong><span class="muted">최근 데이터가 없습니다.</span></div>`;
}

function renderSimulation() {
  const result = state.simulationResult;
  const container = $("#simulateResult");
  if (!container) return;
  if (!result) {
    container.innerHTML = "<dt>결과</dt><dd>아직 실행하지 않았습니다.</dd>";
    $("#simulateFindings").textContent = "";
    return;
  }
  container.innerHTML = `
    <dt>요청 ID</dt><dd>${escapeHtml(result.request_id)}</dd>
    <dt>결정</dt><dd>${actionBadge(result.action)} ${escapeHtml(result.reason || "")}</dd>
    <dt>정책</dt><dd>${escapeHtml(result.policy_id || "")} (v${escapeHtml(result.policy_version || "")})</dd>
    <dt>리스크</dt><dd>${escapeHtml(String(result.risk_score ?? ""))}</dd>
    <dt>탐지 수</dt><dd>${escapeHtml(String(result.finding_count ?? ""))}</dd>
    <dt>라우트</dt><dd>${escapeHtml(JSON.stringify(result.route || null))}</dd>
  `;
  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (findings.length === 0) {
    $("#simulateFindings").textContent = "findings: []";
    return;
  }
  const findingRows = findings.map((finding) => `- ${finding.kind}: ${finding.label}`);
  $("#simulateFindings").textContent = findingRows.join("\n");
}

function clearAdminToken() {
  adminToken = "";
  sessionStorage.removeItem("kaiAdminToken");
  syncAuthInput();
  state.events = [];
  state.policy = null;
  state.privacy = null;
  state.approvals = [];
  state.simulationResult = null;
  refresh();
}

function handleAuthSubmit(event) {
  event.preventDefault();
  adminToken = $("#adminToken").value.trim();
  if (adminToken) {
    sessionStorage.setItem("kaiAdminToken", adminToken);
  } else {
    sessionStorage.removeItem("kaiAdminToken");
  }
  refresh();
}

$("#promptForm").addEventListener("submit", handlePromptSubmit);
$("#authForm").addEventListener("submit", handleAuthSubmit);
$("#policySimulateForm").addEventListener("submit", handlePolicySimulateSubmit);
$("#clearToken").addEventListener("click", clearAdminToken);
$("#sampleMask").addEventListener("click", seedMask);
$("#sampleApproval").addEventListener("click", seedApproval);
$("#refresh").addEventListener("click", refresh);

syncAuthInput();
refresh();
