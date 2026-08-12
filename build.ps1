# build.ps1 - compila los tres binarios en Windows.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $candidates = @("$env:LOCALAPPDATA\Programs\go\bin", "C:\Program Files\Go\bin", "$env:USERPROFILE\go\bin", "C:\Go\bin")
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "go.exe")) { $env:Path = "$c;$env:Path"; break }
    }
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: no se encuentra 'go'. Instalá Go desde https://go.dev/dl/ y volvé a correr." -ForegroundColor Red
        exit 1
    }
}

go build -ldflags="-s -w" -o netscanner.exe ./cmd/scanner
go build -ldflags="-s -w" -o dashboard.exe ./cmd/dashboard
go build -o enrich.exe ./cmd/enrich

Write-Host "Compilado: netscanner.exe dashboard.exe enrich.exe"