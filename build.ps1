<#
.SYNOPSIS
    Gera o executavel do PCCleaner (dist\PCCleaner\PCCleaner.exe).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build.ps1
    powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipTests
#>
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Py = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $Py)) { throw "Python do venv nao encontrado em $Py" }

Write-Host '==> Gerando icone' -ForegroundColor Cyan
& $Py (Join-Path $Root 'assets\make_icon.py')
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar o icone' }

if (-not $SkipTests) {
    Write-Host '==> Executando testes' -ForegroundColor Cyan
    $env:QT_QPA_PLATFORM = 'offscreen'
    & $Py -m pytest -q
    $code = $LASTEXITCODE
    Remove-Item Env:\QT_QPA_PLATFORM -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "Testes falharam (codigo $code). Use -SkipTests para ignorar." }
}

Write-Host '==> PyInstaller (onedir, sem console)' -ForegroundColor Cyan
& $Py -m PyInstaller (Join-Path $Root 'PCCleaner.spec') --noconfirm --clean `
    --workpath (Join-Path $Root 'build') --distpath (Join-Path $Root 'dist')
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller falhou' }

$Exe = Join-Path $Root 'dist\PCCleaner\PCCleaner.exe'
if (-not (Test-Path $Exe)) { throw "Executavel nao encontrado: $Exe" }
$SizeMB = [math]::Round(((Get-ChildItem (Join-Path $Root 'dist\PCCleaner') -Recurse | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Host "OK: $Exe  ($SizeMB MB)" -ForegroundColor Green

$Iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
$Iss = Join-Path $Root 'installer\PCCleaner.iss'
if ((Test-Path $Iscc) -and (Test-Path $Iss)) {
    & $Iscc $Iss
}
