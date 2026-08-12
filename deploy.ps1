# deploy.ps1 - compila todo y despliega el servidor del panel en
# Windows, abriendo el navegador automáticamente.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

.\build.ps1

Get-Process dashboard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath ".\dashboard.exe" -ArgumentList "-file", "casa.jsonl" -WindowStyle Hidden
Start-Sleep -Seconds 2

Start-Process "http://127.0.0.1:8080"
Write-Host "Panel desplegado: http://127.0.0.1:8080"