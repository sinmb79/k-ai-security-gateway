param (
    [string]$BaseUrl = "http://127.0.0.1:8765",
    [string]$AdminToken = "admin-smoke-token"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Error "[smoke-test] $Message"
    exit 1
}

function Invoke-JsonPost([string]$Path, [string]$Body, [hashtable]$Headers = @{}) {
    try {
        return Invoke-RestMethod -Method Post `
            -Uri "$BaseUrl$Path" `
            -ContentType "application/json; charset=utf-8" `
            -Headers $Headers `
            -Body $Body
    }
    catch {
        Fail "POST $Path failed: $($_.Exception.Message)"
    }
}

function Invoke-AdminGet([string]$Path) {
    try {
        return Invoke-RestMethod -Method Get `
            -Uri "$BaseUrl$Path" `
            -Headers @{ Authorization = "Bearer $AdminToken" }
    }
    catch {
        Fail "GET $Path failed: $($_.Exception.Message)"
    }
}

function Invoke-AdminWebGet([string]$Path) {
    try {
        return Invoke-WebRequest -Method Get `
            -Uri "$BaseUrl$Path" `
            -Headers @{ Authorization = "Bearer $AdminToken" } `
            -UseBasicParsing
    }
    catch {
        Fail "GET $Path failed: $($_.Exception.Message)"
    }
}

# Korean prompt, ASCII JSON escaped to avoid Windows PowerShell source-encoding drift.
$piiPromptJson = "\uc785\uae08\uacc4\uc88c 110-123-456789, \ubc95\uc778\ub4f1\ub85d\ubc88\ud638 123456-1234567, \uc8fc\uc18c\ub294 \uc11c\uc6b8\ud2b9\ubcc4\uc2dc \uac15\ub0a8\uad6c \ud14c\ud5e4\ub780\ub85c 123 \uc785\ub2c8\ub2e4."
$chatPayloadJson = @"
{
  "model": "gateway-smoke-test",
  "data_grade": "internal",
  "model_zone": "external",
  "messages": [
    {
      "role": "user",
      "content": "$piiPromptJson"
    }
  ]
}
"@

$chatResponse = Invoke-JsonPost "/v1/chat/completions" $chatPayloadJson

if (-not $chatResponse.gateway_security) {
    Fail "/v1/chat/completions response is missing gateway_security."
}

$requestId = $chatResponse.gateway_security.request_id
if (-not $requestId) {
    Fail "/v1/chat/completions response is missing gateway_security.request_id."
}

$messageContent = $null
try {
    $messageContent = $chatResponse.choices[0].message.content
}
catch {
    Fail "/v1/chat/completions response shape is unexpected."
}

if ($chatResponse.gateway_security.action -ne "mask") {
    Fail "Expected chat action=mask. Actual: $($chatResponse.gateway_security.action)"
}

foreach ($token in @("[ACCOUNT_NO]", "[CORP_REG_NO]", "[ADDRESS]")) {
    if (-not $messageContent.Contains($token)) {
        Fail "Masked response does not contain $token. Response: $messageContent"
    }
}

foreach ($raw in @("110-123-456789", "123456-1234567")) {
    if ($messageContent.Contains($raw)) {
        Fail "Masked response still contains raw value $raw."
    }
}

$simulatePayloadJson = @"
{
  "prompt": "$piiPromptJson",
  "data_grade": "internal",
  "model_zone": "external",
  "user_id": "smoke-user"
}
"@
$simulateResponse = Invoke-JsonPost `
    "/v1/policies/simulate" `
    $simulatePayloadJson `
    @{ Authorization = "Bearer $AdminToken" }

if ($simulateResponse.action -ne "mask") {
    Fail "Expected simulate action=mask. Actual: $($simulateResponse.action)"
}

$simulateRendered = $simulateResponse | ConvertTo-Json -Depth 20 -Compress
foreach ($token in @("[ACCOUNT_NO]", "[CORP_REG_NO]", "[ADDRESS]")) {
    if (-not $simulateRendered.Contains($token)) {
        Fail "Policy simulate output does not contain masked token $token."
    }
}
foreach ($raw in @("110-123-456789", "123456-1234567")) {
    if ($simulateRendered.Contains($raw)) {
        Fail "Policy simulate output still contains raw value $raw."
    }
}

$evidencePackage = Invoke-AdminGet "/v1/reports/evidence-package/$requestId"
if ($evidencePackage.report_type -ne "request_evidence_package") {
    Fail "Evidence package response is invalid."
}
if (-not (($evidencePackage.timeline | ForEach-Object { $_.event_type }) -contains "response_analyzed")) {
    Fail "Evidence package does not include response_analyzed timeline event."
}

$policyResponse = Invoke-AdminGet "/v1/reports/policy"
if (-not $policyResponse.report_type) {
    Fail "/v1/reports/policy response is invalid."
}
if (-not $policyResponse.masked -or [int]$policyResponse.masked -lt 1) {
    Fail "/v1/reports/policy masked count is less than 1."
}
if (-not $policyResponse.request_count -or [int]$policyResponse.request_count -lt 1) {
    Fail "/v1/reports/policy request_count is less than 1."
}

$events = Invoke-AdminGet "/v1/audit/events?request_id=$requestId&event_type=policy_decided&action=mask&order=desc&limit=5"
if (@($events).Count -lt 1) {
    Fail "Filtered audit event search returned no policy_decided mask event."
}

$csvExport = Invoke-AdminWebGet "/v1/audit/events/export?format=csv&request_id=$requestId&event_type=policy_decided&action=mask&order=desc&limit=5"
if (-not ([string]$csvExport.Headers["Content-Type"]).Contains("text/csv")) {
    Fail "CSV export content-type is not text/csv."
}
if (-not ([string]$csvExport.Content).Contains("policy-004-external-korean-pii-mask")) {
    Fail "CSV export does not include expected policy id."
}

$jsonlExport = Invoke-AdminWebGet "/v1/audit/events/export?format=jsonl&request_id=$requestId&event_type=policy_decided&action=mask&order=desc&limit=5"
if (-not ([string]$jsonlExport.Headers["Content-Type"]).Contains("application/x-ndjson")) {
    Fail "JSONL export content-type is not application/x-ndjson."
}
$jsonlText = [string]$jsonlExport.Content
if ($jsonlText.Contains("110-123-456789") -or $jsonlText.Contains("123456-1234567")) {
    Fail "JSONL export contains raw PII."
}

Write-Output "[smoke-test] success: masking, simulation, evidence package, audit search, and export verified"
