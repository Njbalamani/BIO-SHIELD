$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot

function Invoke-Step {
    param(
        [string] $FilePath,
        [string[]] $Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

$VenvPath = Join-Path $ProjectRoot ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
$EnvFile = Join-Path $ProjectRoot ".env"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Invoke-Step -FilePath "py" -Arguments @("-3.12", "-m", "venv", $VenvPath)
}

if (-not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath (Join-Path $ProjectRoot ".env.example") -Destination $EnvFile
}

Invoke-Step -FilePath $VenvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
Invoke-Step -FilePath $VenvPython -Arguments @("-m", "pip", "install", "-r", (Join-Path $ProjectRoot "requirements.txt"))
Invoke-Step -FilePath $VenvPython -Arguments @("manage.py", "migrate")
Invoke-Step -FilePath $VenvPython -Arguments @("manage.py", "collectstatic", "--noinput")

"BioShield setup complete. Run scripts\dev.ps1 to start the development server."
