$ErrorActionPreference = "Stop"

Write-Host "CTI Agent 2 - Startup" -ForegroundColor Cyan
Set-Location $PSScriptRoot
Write-Host "Project folder: $PSScriptRoot"

$pythonCmd = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCmd) {
    $python = "py"
    $pythonArgs = "-3"
} else {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Write-Host "Python was not found. Install Python 3.11 or newer, then run this file again." -ForegroundColor Red
        Read-Host "Press Enter to close"
        exit 1
    }
    $python = "python"
    $pythonArgs = ""
}

if (-not (Test-Path ".venv")) {
    Write-Host "Creating local Python environment..."
    if ($pythonArgs) {
        & $python $pythonArgs -m venv .venv
    } else {
        & $python -m venv .venv
    }
}

Write-Host "Installing requirements..."
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install --no-cache-dir -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ""
    Write-Host "A .env file was created in the project folder." -ForegroundColor Yellow
    Write-Host "Open .env, add your API keys, save it, then run run.bat again."
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 0
}

$port = 8010
if ($env:CTI_AGENT_PORT) {
    $port = [int]$env:CTI_AGENT_PORT
}

Write-Host "Starting CTI Agent 2 at http://127.0.0.1:$port" -ForegroundColor Green
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port $port
