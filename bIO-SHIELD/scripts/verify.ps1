$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot

function Invoke-Step {
    param(
        [string] $Name,
        [string] $FilePath,
        [string[]] $Arguments
    )
    "QA: $Name"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "QA step failed: $Name"
    }
}

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ComposeFile = Join-Path $ProjectRoot "docker\docker-compose.yml"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    throw "Virtual environment not found. Run scripts\setup.ps1 first."
}

Invoke-Step -Name "Python compile" -FilePath $VenvPython -Arguments @("-m", "compileall", "-q", ".")
Invoke-Step -Name "Ruff lint" -FilePath $VenvPython -Arguments @("-m", "ruff", "check", ".")
Invoke-Step -Name "Ruff format" -FilePath $VenvPython -Arguments @("-m", "ruff", "format", "--check", ".")
Invoke-Step -Name "Django checks" -FilePath $VenvPython -Arguments @("manage.py", "check")
Invoke-Step -Name "Migration drift" -FilePath $VenvPython -Arguments @("manage.py", "makemigrations", "--check", "--dry-run")
Invoke-Step -Name "Django tests" -FilePath $VenvPython -Arguments @("manage.py", "test")
Invoke-Step -Name "Synthetic sample generation" -FilePath $VenvPython -Arguments @("samples\generate_synthetic_documents.py")

if (Get-Command docker -ErrorAction SilentlyContinue) {
    Invoke-Step -Name "Docker compose validation" -FilePath "docker" -Arguments @("compose", "-f", $ComposeFile, "config")
}

"All BioShield QA steps passed. Outputs are synthetic only."
