param (
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"

if (-not $env:PYTHONPATH) {
    $env:PYTHONPATH = Join-Path (Get-Location) "src"
}

if (-not $env:KAI_SECURITY_APPROVER_TOKENS) {
    throw "KAI_SECURITY_APPROVER_TOKENS is required. Example: token=manager-1:security_manager"
}

if (-not $env:KAI_SECURITY_ADMIN_TOKENS) {
    throw "KAI_SECURITY_ADMIN_TOKENS is required. Example: admin-token=manager-1:security_manager"
}

if (-not $env:KAI_SECURITY_DB_PATH) {
    $dataDir = Join-Path (Get-Location) "data"
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    $env:KAI_SECURITY_DB_PATH = Join-Path $dataDir "evidence.sqlite3"
}

python -m uvicorn apps.gateway_api.main:app --host 0.0.0.0 --port $Port --reload
