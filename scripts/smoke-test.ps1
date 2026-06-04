param (
    [string]$BaseUrl = "http://127.0.0.1:8765",
    [string]$AdminToken = "admin-smoke-token"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Error "[smoke-test] $Message"
    exit 1
}

$chatPayload = @{
    model = "gateway-smoke-test"
    messages = @(
        @{
            role = "user"
            content = "제 전화번호는 010-1234-5678입니다. 이걸 마스킹해서 요청해줘."
        }
    )
}

try {
    $chatResponse = Invoke-RestMethod -Method Post `
        -Uri "$BaseUrl/v1/chat/completions" `
        -ContentType "application/json" `
        -Body ($chatPayload | ConvertTo-Json -Depth 20)
}
catch {
    Fail "POST /v1/chat/completions 요청에 실패했습니다: $($_.Exception.Message)"
}

if (-not $chatResponse.gateway_security) {
    Fail "/v1/chat/completions 응답에 gateway_security 필드가 없습니다."
}

$messageContent = $null
try {
    $messageContent = $chatResponse.choices[0].message.content
}
catch {
    Fail "/v1/chat/completions 응답 형식이 예상과 다릅니다."
}

if ($chatResponse.gateway_security.action -ne "mask") {
    Fail "예상 action=mask가 아닙니다. 실제: $($chatResponse.gateway_security.action)"
}

if (-not ($messageContent.Contains("[PHONE]"))) {
    Fail "마스킹 토큰([PHONE])이 응답에 포함되지 않았습니다. 응답: $messageContent"
}

if ($messageContent -match "010-\\d{3,4}-\\d{4}") {
    Fail "마스킹되지 않은 휴대폰 번호 패턴이 응답에 남아 있습니다."
}

try {
    $policyResponse = Invoke-RestMethod -Method Get `
        -Uri "$BaseUrl/v1/reports/policy" `
        -Headers @{ Authorization = "Bearer $AdminToken" }
}
catch {
    Fail "GET /v1/reports/policy 요청에 실패했습니다: $($_.Exception.Message)"
}

if (-not $policyResponse.report_type) {
    Fail "/v1/reports/policy 응답이 비정상입니다."
}

if (-not $policyResponse.masked -or [int]$policyResponse.masked -lt 1) {
    Fail "/v1/reports/policy 응답의 masked 값이 1 미만입니다."
}

if (-not $policyResponse.request_count -or [int]$policyResponse.request_count -lt 1) {
    Fail "/v1/reports/policy 요청 건수가 1 미만입니다."
}

Write-Output "[smoke-test] success: chat completions masking and policy report verified"
