param(
    [string]$CidrList = "203.0.113.0/24,198.51.100.0/24,192.0.2.0/24",
    [string]$Ports = "80,443,8080,8000,554,21,22,5000,5001,8081,9000",
    [int]$Workers = 400,
    [int]$Timeout = 1500,
    [string]$Output = "data\isp_total.jsonl",
    [string]$StatsFile = "data\isp_total.jsonl.stats",
    [int]$WebPort = 8080,
    [string]$Proxy = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

New-Item -ItemType Directory -Path data -Force | Out-Null
Get-Process dashboard -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item $Output -ErrorAction SilentlyContinue
Remove-Item $StatsFile -ErrorAction SilentlyContinue

$dash = Start-Process -FilePath ".\dashboard.exe" -ArgumentList "-file", $Output, "-addr", "127.0.0.1:$WebPort", "-stats", $StatsFile -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 800
Start-Process "http://127.0.0.1:$WebPort"

foreach ($cidr in $CidrList -split ",") {
    Write-Host ">> escaneando $cidr (workers=$Workers timeout=${Timeout}ms) -> $Output"
    $proxyArgs = @()
    if ($Proxy) { $proxyArgs = @("--proxy", $Proxy) }
    & .\netscanner.exe -c $cidr -p $Ports -w $Workers -t $Timeout -o $Output --stats $StatsFile --ftp-ports 21 @proxyArgs
}

if (Test-Path ".\enrich.exe") {
    Write-Host ">> geolocalizando IPs (ciudades, coordenadas, ISP) -> $($Output -replace '\.jsonl$','_geo.jsonl')"
    & .\enrich.exe -in $Output -out ($Output -replace "\.jsonl$", "_geo.jsonl")
    $GeoOutput = $Output -replace "\.jsonl$", "_geo.jsonl"
    $proxyArgs = @()
    if ($Proxy) { $proxyArgs = @("--proxy", $Proxy) }
    Stop-Process -Id $dash.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    $dash = Start-Process -FilePath ".\dashboard.exe" -ArgumentList @("-file", $GeoOutput, "-addr", "127.0.0.1:$WebPort", "-stats", $StatsFile) + $proxyArgs -WindowStyle Hidden -PassThru
    Write-Host ">> mapa disponible con coordenadas (panel recargado sobre $GeoOutput)."
} else {
    Write-Host ">> aviso: enrich.exe no existe (make enrich) - el mapa no tendrá coordenadas."
}

Write-Host ""
Write-Host ">> escaneo completo. Resultados en $Output. Presiona Enter para cerrar el panel."
$null = Read-Host
Stop-Process -Id $dash.Id -Force -ErrorAction SilentlyContinue
