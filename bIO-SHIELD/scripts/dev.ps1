param(
    [string] $HostAddress = "127.0.0.1",
    [int] $Port = 8000
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    throw "Virtual environment not found. Run scripts\setup.ps1 first."
}

& $VenvPython manage.py check
if ($LASTEXITCODE -ne 0) {
    throw "Django configuration check failed."
}

& $VenvPython manage.py runserver "${HostAddress}:${Port}"
if ($LASTEXITCODE -ne 0) {
    throw "Development server exited with code $LASTEXITCODE."
}
