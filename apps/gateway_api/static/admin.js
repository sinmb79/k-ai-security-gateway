const state = {
  events: [],
  policy: null,
  privacy: null,
  approvals: [],
  policySummary: null,
  simulationResult: null,
  evidencePackage: null,
  lastApprovalCompletion: null,
  approvalUiState: {},
  approvalDraftComments: {},
  eventFilters: {
    request_id: "",
    event_type: "",
    action: "",
    policy_id: "",
    order: "desc",
    limit: "100",
  },
};

const $ = (selector) => document.querySelector(selector);
const APPROVAL_STATUS = {
  IDLE: "idle",
  PROCESSING: "processing",
  SUCCESS: "success",
  ERROR: "error",
};

let adminToken = "";
let approverToken = "";

function syncAuthInput() {
  const input = $("#adminToken");
  if (input) {
    input.value = adminToken;
  }
}

function syncApproverInput() {
  const input = $("#approverToken");
  if (input) {
    input.value = approverToken;
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

function setApprovalActionStatus(message, level = APPROVAL_STATUS.IDLE) {
  const statusElement = $("#approvalActionStatus");
  if (!statusElement) return;
  statusElement.textContent = message;
  statusElement.classList.remove(
    "status-idle",
    "status-processing",
    "status-success",
    "status-error",
  );
  statusElement.classList.add(`status-${level}`);
}

function getApprovalItemUiState(approvalId) {
  return state.approvalUiState[approvalId] || {
    status: APPROVAL_STATUS.IDLE,
    message: "대기",
  };
}

function setApprovalItemUiState(approvalId, status, message) {
  state.approvalUiState[approvalId] = { status, message };
}

function clearApprovalActionState(approvalId) {
  if (approvalId) {
    delete state.approvalUiState[approvalId];
    return;
  }
  state.approvalUiState = {};
}

function extractCompletionContent(completion) {
  const choice = completion?.choices?.[0];
  const content = choice?.message?.content;
  return typeof content === "string" ? content : "";
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

function buildEventQuery(extra = {}) {
  const params = new URLSearchParams();
  const filters = { ...state.eventFilters, ...extra };
  Object.entries(filters).forEach(([key, value]) => {
    const normalized = String(value ?? "").trim();
    if (normalized) {
      params.set(key, normalized);
    }
  });
  return params.toString();
}

async function fetchAuditEvents() {
  const query = buildEventQuery();
  return fetchJson(`/v1/audit/events${query ? `?${query}` : ""}`, { admin: true });
}

async function fetchAuditEventExport(format) {
  if (!adminToken) {
    throw new Error("admin token is required");
  }
  const query = buildEventQuery({ format });
  const response = await fetch(`/v1/audit/events/export?${query}`, {
    headers: withAdminHeaders(),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${text}`);
  }
  return response.text();
}

function downloadText(filename, content, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
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

async function fetchEvidencePackage(requestId) {
  return fetchJson(`/v1/reports/evidence-package/${encodeURIComponent(requestId)}`, {
    admin: true,
  });
}

async function resolveApproval(approvalId, approved, comment) {
  return fetchJson(`/v1/approvals/${encodeURIComponent(approvalId)}/resolve`, {
    admin: true,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      approval_token: approverToken,
      approved: !!approved,
      comment: comment || "",
    }),
  });
}

async function refresh() {
  if (!adminToken) {
    clearApprovalActionState();
    state.events = [];
    state.policy = null;
    state.privacy = null;
    state.approvals = [];
    state.simulationResult = null;
    state.evidencePackage = null;
    state.lastApprovalCompletion = null;
    render();
    $("#serverStatus").textContent = "API authorization required";
    $("#eventFilterStatus").textContent = "관리자 토큰 필요";
    setApprovalActionStatus("Need admin token");
    setEvidencePackageStatus("Need admin token", APPROVAL_STATUS.ERROR);
    return;
  }
  try {
    const [events, policyReport, privacy, approvals, policySummary] = await Promise.all([
      fetchAuditEvents(),
      fetchJson("/v1/reports/policy", { admin: true }),
      fetchJson("/v1/reports/privacy-export", { admin: true }),
      fetchJson("/v1/approvals/pending", { admin: true }),
      fetchPolicies(),
    ]);
    state.events = events;
    state.policy = policyReport;
    state.privacy = privacy;
    state.approvals = approvals;
    state.policySummary = policySummary;
    render();
    $("#serverStatus").textContent = "API reachable";
    $("#eventFilterStatus").textContent = "검색 완료";
    setApprovalActionStatus("Ready");
  } catch (error) {
    clearApprovalActionState();
    state.events = [];
    state.policy = null;
    state.privacy = null;
    state.approvals = [];
    state.policySummary = null;
    state.simulationResult = null;
    state.evidencePackage = null;
    state.lastApprovalCompletion = null;
    render();
    $("#serverStatus").textContent = "API error";
    $("#eventFilterStatus").textContent = `검색 실패: ${error.message}`;
    setApprovalActionStatus(`Load failed: ${error.message}`, APPROVAL_STATUS.ERROR);
    setEvidencePackageStatus(`Load failed: ${error.message}`, APPROVAL_STATUS.ERROR);
    console.error(error);
  }
}

function getDefaultApprovalComment() {
  const input = $("#defaultApprovalComment");
  return input ? input.value.trim() : "";
}

function handleApproverTokenInput() {
  approverToken = $("#approverToken").value.trim();
  if (approverToken) {
    setApprovalActionStatus("Approver token set", APPROVAL_STATUS.SUCCESS);
  } else {
    setApprovalActionStatus("Approver token removed", APPROVAL_STATUS.IDLE);
  }
  renderApprovals();
}

function clearApproverToken() {
  approverToken = "";
  syncApproverInput();
  setApprovalActionStatus("Approver token cleared", APPROVAL_STATUS.IDLE);
  renderApprovals();
}

function setEvidencePackageStatus(message, level = APPROVAL_STATUS.IDLE) {
  const statusElement = $("#evidencePackageStatus");
  if (!statusElement) return;
  statusElement.textContent = message;
  statusElement.classList.remove(
    "status-idle",
    "status-processing",
    "status-success",
    "status-error",
  );
  statusElement.classList.add(`status-${level}`);
}

async function loadEvidencePackage(requestId) {
  const trimmedRequestId = String(requestId || "").trim();
  if (!trimmedRequestId) {
    state.evidencePackage = null;
    setEvidencePackageStatus("요청 ID 필요", APPROVAL_STATUS.ERROR);
    renderEvidencePackage();
    return;
  }
  if (!adminToken) {
    state.evidencePackage = null;
    setEvidencePackageStatus("관리자 토큰 필요", APPROVAL_STATUS.ERROR);
    renderEvidencePackage();
    return;
  }

  $("#evidenceRequestId").value = trimmedRequestId;
  setEvidencePackageStatus("조회 중...", APPROVAL_STATUS.PROCESSING);
  try {
    state.evidencePackage = await fetchEvidencePackage(trimmedRequestId);
    setEvidencePackageStatus("조회 완료", APPROVAL_STATUS.SUCCESS);
  } catch (error) {
    state.evidencePackage = null;
    setEvidencePackageStatus(`조회 실패: ${error.message}`, APPROVAL_STATUS.ERROR);
  }
  renderEvidencePackage();
}

function handleApprovalCommentInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLTextAreaElement)) return;
  if (!target.classList.contains("approval-item-comment")) return;
  const item = target.closest(".approval-item");
  if (!item) return;
  const approvalId = item.dataset.approvalId;
  if (!approvalId) return;
  state.approvalDraftComments[approvalId] = target.value;
}

async function handleApprovalActionClick(event) {
  const button = event.target;
  if (!(button instanceof HTMLButtonElement)) return;
  const action = button.dataset.action;
  if (action !== "approve" && action !== "reject") return;

  const item = button.closest(".approval-item");
  if (!item) return;
  const approvalId = item.dataset.approvalId;
  if (!approvalId) return;

  const statusElement = item.querySelector(".approval-item-status");
  const statusControl = statusElement || null;
  const actionButtons = item.querySelectorAll('button[data-action]');

  if (!adminToken) {
    setApprovalItemUiState(approvalId, APPROVAL_STATUS.ERROR, "Missing admin token");
    setApprovalActionStatus("Missing admin token", APPROVAL_STATUS.ERROR);
    if (statusControl) {
      statusControl.textContent = "Missing admin token";
      statusControl.classList.remove("status-idle", "status-processing", "status-success", "status-error");
      statusControl.classList.add("status-error");
    }
    return;
  }

  if (!approverToken) {
    setApprovalItemUiState(
      approvalId,
      APPROVAL_STATUS.ERROR,
      "Approver token is required",
    );
    setApprovalActionStatus("Approver token is required", APPROVAL_STATUS.ERROR);
    if (statusControl) {
      statusControl.textContent = "Approver token is required";
      statusControl.classList.remove("status-idle", "status-processing", "status-success", "status-error");
      statusControl.classList.add("status-error");
    }
    return;
  }

  const selectedComment = state.approvalDraftComments[approvalId] || "";
  const fallbackComment = getDefaultApprovalComment();
  const comment = selectedComment.trim() || fallbackComment;
  const approved = action === "approve";
  actionButtons.forEach((actionButton) => {
    actionButton.disabled = true;
  });
  setApprovalItemUiState(approvalId, APPROVAL_STATUS.PROCESSING, "처리 중...");
  if (statusControl) {
    statusControl.textContent = "처리 중...";
    statusControl.classList.remove("status-idle", "status-processing", "status-success", "status-error");
    statusControl.classList.add("status-processing");
  }

  try {
    const result = await resolveApproval(approvalId, approved, comment);
    const completionContent = approved ? extractCompletionContent(result.completion) : "";
    if (completionContent) {
      state.lastApprovalCompletion = {
        approvalId,
        requestId: result.request_id,
        deliveryMode: result.completion_delivery?.mode || "approval_resolve_response",
        content: completionContent,
      };
    }
    const successMessage = approved
      ? completionContent
        ? "승인 처리 및 모델 응답 수신 완료"
        : "승인 처리 완료"
      : "반려 처리 완료";
    setApprovalItemUiState(
      approvalId,
      APPROVAL_STATUS.SUCCESS,
      successMessage,
    );
    delete state.approvalDraftComments[approvalId];
    await refresh();
    setApprovalActionStatus(successMessage, APPROVAL_STATUS.SUCCESS);
  } catch (error) {
    const errorState = `실패: ${error.message}`;
    setApprovalItemUiState(approvalId, APPROVAL_STATUS.ERROR, errorState);
    if (statusControl) {
      statusControl.textContent = errorState;
      statusControl.classList.remove("status-idle", "status-processing", "status-success", "status-error");
      statusControl.classList.add("status-error");
    }
    setApprovalActionStatus(errorState, APPROVAL_STATUS.ERROR);
    actionButtons.forEach((actionButton) => {
      actionButton.disabled = false;
    });
  }
}

async function handlePromptSubmit(event) {
  event.preventDefault();
  const prompt = $("#promptInput").value.trim();
  const dataGrade = $("#dataGrade").value;
  if (!prompt || !dataGrade) return;
  setEvidencePackageStatus("요청 전송 중...", APPROVAL_STATUS.PROCESSING);
  try {
    const result = await submitPrompt(prompt, dataGrade);
    const requestId = result.gateway_security?.request_id;
    await refresh();
    if (requestId) {
      await loadEvidencePackage(requestId);
    }
  } catch (error) {
    state.evidencePackage = null;
    renderEvidencePackage();
    $("#serverStatus").textContent = "Request failed";
    setApprovalActionStatus(`Request failed: ${error.message}`, APPROVAL_STATUS.ERROR);
    setEvidencePackageStatus(`요청 실패: ${error.message}`, APPROVAL_STATUS.ERROR);
  }
}

async function handleEvidencePackageSubmit(event) {
  event.preventDefault();
  await loadEvidencePackage($("#evidenceRequestId").value);
}

function readEventFiltersFromForm() {
  state.eventFilters = {
    request_id: $("#eventRequestId").value.trim(),
    event_type: $("#eventTypeFilter").value,
    action: $("#eventActionFilter").value,
    policy_id: $("#eventPolicyIdFilter").value.trim(),
    order: $("#eventOrderFilter").value || "desc",
    limit: $("#eventLimitFilter").value.trim() || "100",
  };
}

function syncEventFilterForm() {
  $("#eventRequestId").value = state.eventFilters.request_id;
  $("#eventTypeFilter").value = state.eventFilters.event_type;
  $("#eventActionFilter").value = state.eventFilters.action;
  $("#eventPolicyIdFilter").value = state.eventFilters.policy_id;
  $("#eventOrderFilter").value = state.eventFilters.order || "desc";
  $("#eventLimitFilter").value = state.eventFilters.limit || "100";
}

async function handleEventFilterSubmit(event) {
  event.preventDefault();
  readEventFiltersFromForm();
  $("#eventFilterStatus").textContent = "검색 중...";
  await refresh();
}

async function clearEventFilters() {
  state.eventFilters = {
    request_id: "",
    event_type: "",
    action: "",
    policy_id: "",
    order: "desc",
    limit: "100",
  };
  syncEventFilterForm();
  $("#eventFilterStatus").textContent = "필터 초기화";
  await refresh();
}

async function handleEventExportClick(event) {
  const button = event.target;
  if (!(button instanceof HTMLButtonElement)) return;
  const format = button.dataset.format;
  if (format !== "csv" && format !== "jsonl") return;

  readEventFiltersFromForm();
  $("#eventFilterStatus").textContent = `${format.toUpperCase()} 생성 중...`;
  try {
    const content = await fetchAuditEventExport(format);
    const timestamp = new Date().toISOString().replaceAll(":", "-").slice(0, 19);
    if (format === "csv") {
      downloadText(`kai-audit-events-${timestamp}.csv`, content, "text/csv;charset=utf-8");
    } else {
      downloadText(
        `kai-audit-events-${timestamp}.jsonl`,
        content,
        "application/x-ndjson;charset=utf-8",
      );
    }
    $("#eventFilterStatus").textContent = `${format.toUpperCase()} 다운로드 준비 완료`;
  } catch (error) {
    $("#eventFilterStatus").textContent = `내보내기 실패: ${error.message}`;
  }
}

async function handleEventTableClick(event) {
  const button = event.target;
  if (!(button instanceof HTMLButtonElement)) return;
  const requestId = button.dataset.requestId;
  if (!requestId) return;
  await loadEvidencePackage(requestId);
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
  $("#promptInput").value = "전화번호 010-1234-5678를 감지해서 처리";
}

function seedApproval() {
  $("#promptInput").value = "API key and secret should be reviewed";
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
  renderApprovalExecutionResult();
  renderRouting();
  renderSimulation();
  renderEvidencePackage();
}

function renderApprovalExecutionResult() {
  const container = $("#approvalExecutionResult");
  if (!container) return;
  const result = state.lastApprovalCompletion;
  container.replaceChildren();
  if (!result) {
    container.hidden = true;
    return;
  }
  container.hidden = false;

  const title = document.createElement("strong");
  title.textContent = "최근 승인 실행 응답";
  const meta = document.createElement("span");
  meta.className = "muted";
  meta.textContent = `요청 ${shortId(result.requestId)} / 승인 ${shortId(result.approvalId)} / ${result.deliveryMode}`;
  const content = document.createElement("pre");
  content.textContent = result.content;
  container.append(title, meta, content);
}

function renderEvents() {
  const rows = state.events.slice(0, 50).map((event) => {
    const action = event.payload?.action || event.payload?.status || "";
    const policyId = event.payload?.policy_id || event.payload?.approval_id || "-";
    const requestId = escapeHtml(event.request_id);
    return `<tr>
      <td>${formatTime(event.timestamp)}</td>
      <td title="${escapeHtml(event.event_type)}">${escapeHtml(event.event_type)}</td>
      <td><button type="button" class="link-button event-request-button" data-request-id="${requestId}">${escapeHtml(shortId(event.request_id))}</button></td>
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
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`)
          .join(", ");
        const route = policy.route_model_zone ? ` (${policy.route_model_zone})` : "";
        return `<li><span title="${escapeHtml(when)}">${escapeHtml(policy.id)}</span><strong>${actionBadge(policy.action)}${escapeHtml(route)}</strong></li>`;
      })
      .join("") || `<li><span>정책이 없습니다.</span><strong>0</strong></li>`;
}

function renderApprovals() {
  const list = $("#approvalList");
  if (!list) return;

  list.replaceChildren();
  if (!state.approvals.length) {
    const empty = document.createElement("div");
    empty.className = "approval-item";
    const message = document.createElement("strong");
    const detail = document.createElement("span");
    message.textContent = "대기 요청 없음";
    detail.className = "muted";
    detail.textContent = "현재 처리할 승인 항목이 없습니다.";
    empty.append(message, detail);
    list.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  state.approvals.slice(0, 6).forEach((approval) => {
    const item = document.createElement("div");
    item.className = "approval-item";
    item.dataset.approvalId = approval.approval_id;

    const header = document.createElement("strong");
    header.textContent = `${shortId(approval.approval_id)} / ${approval.status || "pending"}`;

    const reason = document.createElement("span");
    reason.textContent = approval.reason || "";

    const metadata = document.createElement("span");
    metadata.className = "muted";
    metadata.textContent = `요청 ${shortId(approval.request_id)} / ${approval.requested_by || ""}`;

    const executionNotice = document.createElement("span");
    executionNotice.className = "muted";
    const executionParts = [];
    if (approval.last_execution_error) {
      executionParts.push(`last error: ${approval.last_execution_error}`);
    }
    if (approval.recommended_action) {
      executionParts.push(`action: ${approval.recommended_action}`);
    }
    executionNotice.textContent = executionParts.join(" / ");

    const status = document.createElement("span");
    const statusState = getApprovalItemUiState(approval.approval_id);
    status.className = `approval-item-status status-${statusState.status}`;
    status.textContent =
      statusState.message ||
      (approval.can_execute === false ? "Operator review required" : "");

    const comment = document.createElement("textarea");
    comment.className = "approval-item-comment";
    comment.rows = 2;
    comment.placeholder = "항목별 코멘트(선택)";
    comment.value = state.approvalDraftComments[approval.approval_id] || "";

    const actions = document.createElement("div");
    actions.className = "approval-item-actions";
    const approveButton = document.createElement("button");
    const rejectButton = document.createElement("button");
    approveButton.type = "button";
    rejectButton.type = "button";
    approveButton.textContent = "승인";
    rejectButton.textContent = "반려";
    approveButton.dataset.action = "approve";
    rejectButton.dataset.action = "reject";
    const isBusy = statusState.status === APPROVAL_STATUS.PROCESSING;
    const baseDisabled = !adminToken || !approverToken || isBusy;
    const executionDisabled = approval.can_execute === false || approval.retryable === false;
    approveButton.disabled = baseDisabled || executionDisabled;
    approveButton.title = executionDisabled ? "Operator review required" : "";
    rejectButton.disabled = baseDisabled;

    actions.append(approveButton, rejectButton);
    item.append(header, reason, metadata);
    if (executionNotice.textContent) {
      item.append(executionNotice);
    }
    item.append(status, comment, actions);
    fragment.appendChild(item);
  });
  list.appendChild(fragment);
}

function renderRouting() {
  const routed = state.events
    .filter((event) => event.event_type === "policy_decided")
    .slice(0, 5)
    .map((event) => {
      const action = event.payload?.action || "unknown";
      return `<div class="routing-item">
        <strong>${actionBadge(action)} ${escapeHtml(event.payload?.policy_id || "")}</strong>
        <span class="muted">요청 ${escapeHtml(shortId(event.request_id))} / ${event.payload?.effective_prompt_changed ? "변경됨" : "미변경"}</span>
      </div>`;
    });
  $("#routingList").innerHTML =
    routed.join("") || `<div class="routing-item"><strong>정책 결정 내역 없음</strong><span class="muted">최근 경로 결과가 없습니다.</span></div>`;
}

function renderSimulation() {
  const result = state.simulationResult;
  const container = $("#simulateResult");
  if (!container) return;
  if (!result) {
    container.innerHTML = "<dt>결과</dt><dd>시뮬레이션을 실행해 주세요.</dd>";
    $("#simulateFindings").textContent = "";
    return;
  }
  container.innerHTML = `
    <dt>요청 ID</dt><dd>${escapeHtml(result.request_id)}</dd>
    <dt>결정</dt><dd>${actionBadge(result.action)} ${escapeHtml(result.reason || "")}</dd>
    <dt>정책</dt><dd>${escapeHtml(result.policy_id || "")} (v${escapeHtml(result.policy_version || "")})</dd>
    <dt>위험점수</dt><dd>${escapeHtml(String(result.risk_score ?? ""))}</dd>
    <dt>이슈수</dt><dd>${escapeHtml(String(result.finding_count ?? ""))}</dd>
    <dt>라우팅</dt><dd>${escapeHtml(JSON.stringify(result.route || null))}</dd>
  `;
  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (findings.length === 0) {
    $("#simulateFindings").textContent = "findings: []";
    return;
  }
  const findingRows = findings.map((finding) => `- ${finding.kind}: ${finding.label}`);
  $("#simulateFindings").textContent = findingRows.join("\n");
}

function renderEvidencePackage() {
  const summary = $("#evidenceSummary");
  const timeline = $("#evidenceTimeline");
  if (!summary || !timeline) return;

  const report = state.evidencePackage;
  timeline.replaceChildren();
  if (!report) {
    summary.innerHTML = "<dt>상태</dt><dd>요청 없음</dd>";
    return;
  }

  const chain = report.chain_verification || {};
  const policy = report.policy_decision || {};
  const route = report.route_decision || {};
  const approval = report.approval || {};
  summary.innerHTML = `
    <dt>요청 ID</dt><dd>${escapeHtml(report.request_id || "")}</dd>
    <dt>증거 상태</dt><dd>${escapeHtml(report.evidence_status || "")}</dd>
    <dt>체인 검증</dt><dd>${escapeHtml(chain.status || String(report.chain_verified))} / ${escapeHtml(String(chain.event_count ?? report.event_count ?? 0))} events</dd>
    <dt>정책</dt><dd>${actionBadge(policy.action || "unknown")} ${escapeHtml(policy.policy_id || "")}</dd>
    <dt>라우팅</dt><dd>${escapeHtml(route.reason || JSON.stringify(route.route || null))}</dd>
    <dt>승인</dt><dd>${escapeHtml(approval.approval_resolved?.status || approval.approval_requested?.status || "not_requested")}</dd>
  `;

  const events = Array.isArray(report.timeline) ? report.timeline : [];
  if (events.length === 0) {
    const empty = document.createElement("div");
    empty.className = "evidence-timeline-empty";
    empty.textContent = "타임라인 이벤트가 없습니다.";
    timeline.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  events.forEach((event) => {
    const item = document.createElement("div");
    item.className = "evidence-timeline-item";

    const header = document.createElement("div");
    header.className = "evidence-timeline-head";
    const title = document.createElement("strong");
    title.textContent = `${event.event_type || "event"} / ${shortId(event.event_id)}`;
    const time = document.createElement("span");
    time.className = "muted";
    time.textContent = formatTime(event.timestamp);
    header.append(title, time);

    const hashes = document.createElement("span");
    hashes.className = "muted evidence-hash";
    hashes.textContent = `hash ${shortId(event.event_hash)} / prev ${shortId(event.previous_hash)}`;

    const payload = document.createElement("pre");
    payload.textContent = JSON.stringify(event.payload || {}, null, 2);

    item.append(header, hashes, payload);
    fragment.appendChild(item);
  });
  timeline.appendChild(fragment);
}

function clearAdminToken() {
  adminToken = "";
  syncAuthInput();
  state.events = [];
  state.policy = null;
  state.privacy = null;
  state.approvals = [];
  state.simulationResult = null;
  state.evidencePackage = null;
  clearApprovalActionState();
  renderEvidencePackage();
  refresh();
}

function handleAuthSubmit(event) {
  event.preventDefault();
  adminToken = $("#adminToken").value.trim();
  refresh();
}

$("#promptForm").addEventListener("submit", handlePromptSubmit);
$("#authForm").addEventListener("submit", handleAuthSubmit);
$("#policySimulateForm").addEventListener("submit", handlePolicySimulateSubmit);
$("#evidencePackageForm").addEventListener("submit", handleEvidencePackageSubmit);
$("#eventFilterForm").addEventListener("submit", handleEventFilterSubmit);
$("#clearToken").addEventListener("click", clearAdminToken);
$("#clearEventFilters").addEventListener("click", clearEventFilters);
$("#approverToken").addEventListener("input", handleApproverTokenInput);
$("#clearApproverToken").addEventListener("click", clearApproverToken);
$("#approvalList").addEventListener("click", handleApprovalActionClick);
$("#approvalList").addEventListener("input", handleApprovalCommentInput);
$("#eventRows").addEventListener("click", handleEventTableClick);
document.querySelectorAll(".export-button").forEach((button) => {
  button.addEventListener("click", handleEventExportClick);
});
$("#sampleMask").addEventListener("click", seedMask);
$("#sampleApproval").addEventListener("click", seedApproval);
$("#refresh").addEventListener("click", refresh);

syncAuthInput();
syncApproverInput();
syncEventFilterForm();
setApprovalActionStatus("Ready");
setEvidencePackageStatus("미조회");
refresh();
