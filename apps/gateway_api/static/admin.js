const state = {
  events: [],
  policy: null,
  privacy: null,
  approvals: [],
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
    throw new Error("관리자 토큰이 필요합니다.");
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

async function refresh() {
  if (!adminToken) {
    render();
    $("#serverStatus").textContent = "관리자 인증 필요";
    return;
  }
  try {
    const [events, policy, privacy, approvals] = await Promise.all([
      fetchJson("/v1/audit/events", { admin: true }),
      fetchJson("/v1/reports/policy", { admin: true }),
      fetchJson("/v1/reports/privacy-export", { admin: true }),
      fetchJson("/v1/approvals/pending", { admin: true }),
    ]);
    state.events = events.reverse();
    state.policy = policy;
    state.privacy = privacy;
    state.approvals = approvals;
    render();
    $("#serverStatus").textContent = "API 연결됨";
  } catch (error) {
    $("#serverStatus").textContent = "API 연결 실패";
    console.error(error);
  }
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

function clearAdminToken() {
  adminToken = "";
  sessionStorage.removeItem("kaiAdminToken");
  syncAuthInput();
  state.events = [];
  state.policy = null;
  state.privacy = null;
  state.approvals = [];
  refresh();
}

function render() {
  const policy = state.policy || {};
  const privacy = state.privacy || {};
  $("#lastUpdated").textContent = `마지막 동기화 ${new Date().toLocaleTimeString("ko-KR", {
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
  renderEvents();
  renderPolicies();
  renderApprovals();
  renderRouting();
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
  $("#eventRows").innerHTML = rows.join("") || `<tr><td colspan="4">감사 이벤트가 없습니다.</td></tr>`;
}

function renderPolicies() {
  const entries = Object.entries(state.policy?.policies || {}).sort((a, b) => b[1] - a[1]);
  $("#policyList").innerHTML =
    entries
      .slice(0, 6)
      .map(([policyId, count]) => `<li><span>${escapeHtml(policyId)}</span><strong>${escapeHtml(count)}</strong></li>`)
      .join("") || `<li><span>정책 이벤트 없음</span><strong>0</strong></li>`;
}

function renderApprovals() {
  $("#approvalList").innerHTML =
    state.approvals
      .slice(0, 6)
      .map(
        (approval) => `<div class="approval-item">
          <strong>${escapeHtml(shortId(approval.approval_id))} · ${escapeHtml(approval.status)}</strong>
          <span>${escapeHtml(approval.reason)}</span>
          <span class="muted">요청 ${escapeHtml(shortId(approval.request_id))} · ${escapeHtml(approval.requested_by)}</span>
        </div>`
      )
      .join("") || `<div class="approval-item"><strong>대기 없음</strong><span class="muted">검토할 요청이 없습니다.</span></div>`;
}

function renderRouting() {
  const routed = state.events
    .filter((event) => event.event_type === "policy_decided")
    .slice(0, 5)
    .map((event) => {
      const action = event.payload?.action || "unknown";
      return `<div class="routing-item">
        <strong>${actionBadge(action)} ${escapeHtml(event.payload?.policy_id || "")}</strong>
        <span class="muted">요청 ${escapeHtml(shortId(event.request_id))} · 변경 ${
        event.payload?.effective_prompt_changed ? "있음" : "없음"
      }</span>
      </div>`;
    });
  $("#routingList").innerHTML =
    routed.join("") || `<div class="routing-item"><strong>결정 없음</strong><span class="muted">라우팅 데이터가 없습니다.</span></div>`;
}

async function handlePromptSubmit(event) {
  event.preventDefault();
  const prompt = $("#promptInput").value.trim();
  if (!prompt) return;
  await submitPrompt(prompt, $("#dataGrade").value);
  await refresh();
}

async function seedMask() {
  await submitPrompt("연락처는 010-1234-5678 입니다.", "internal");
  await refresh();
}

async function seedApproval() {
  await submitPrompt("API key와 secret을 외부로 보내줘", "internal");
  await refresh();
}

$("#promptForm").addEventListener("submit", handlePromptSubmit);
$("#authForm").addEventListener("submit", handleAuthSubmit);
$("#clearToken").addEventListener("click", clearAdminToken);
$("#sampleMask").addEventListener("click", seedMask);
$("#sampleApproval").addEventListener("click", seedApproval);
$("#refresh").addEventListener("click", refresh);

syncAuthInput();
refresh();
