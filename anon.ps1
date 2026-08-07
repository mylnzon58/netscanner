# anon.ps1 - installs and starts a private Tor SOCKS5 proxy inside the
# project (tools\tor) so netscanner can run anonymously without external
# dependencies. The proxy listens on 127.0.0.1:9050.
#
# Usage:      .\anon.ps1            (install + start, repeat starts only)
#             .\anon.ps1 -Stop
#             .\anon.ps1 -Check
#
# After it is running, use:  --proxy socks5://127.0.0.1:9050

param(
    [switch]$Stop,
    [switch]$Check
)

$ErrorActionPreference = "Stop"

$TorDir   = Join-Path $PSScriptRoot "tools\tor"
$TorExe   = Join-Path $TorDir "tor.exe"
$Torrc    = Join-Path $TorDir "torrc"
$DataDir  = Join-Path $TorDir "data"
$LogFile  = Join-Path $TorDir "tor.log"
$SocksPort = 9050

if ($Stop) {
    Get-Process tor -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "Tor detenido."
    exit 0
}

if ($Check) {
    $alive = Test-NetConnection -ComputerName 127.0.0.1 -Port $SocksPort -WarningAction SilentlyContinue
    if ($alive.TcpTestSucceeded) {
        Write-Host "TOR ACTIVO en 127.0.0.1:$SocksPort"
        exit 0
    }
    Write-Host "TOR NO activo. Ejecuta: .\anon.ps1"
    exit 1
}

if (-not (Test-Path $TorExe)) {
    Write-Host "Tor no esta instalado en tools\tor. Descargando Expert Bundle oficial..."

    New-Item -ItemType Directory -Path $TorDir -Force | Out-Null

    $index = "https://archive.torproject.org/tor-package-archive/torbrowser/"
    $html = (Invoke-WebRequest -UseBasicParsing -Uri $index -TimeoutSec 30).Content
    $versions = [regex]::Matches($html, 'href="(\d+\.\d+\.\d+)/"') |
        ForEach-Object { [version]$_.Groups[1].Value } |
        Sort-Object -Descending -Unique
    if (-not $versions) {
        Write-Host "ERROR: no se pudo leer la lista de versiones de Tor. Revisa la conexion." -ForegroundColor Red
        exit 1
    }

    $tmp = Join-Path $env:TEMP "tor-expert-bundle.tar.gz"
    $downloaded = $false
    foreach ($ver in $versions[0..([Math]::Min(4, $versions.Count - 1))]) {
        $file = "tor-expert-bundle-windows-x86_64-$ver.tar.gz"
        $url  = "$index$ver/$file"
        try {
            Write-Host "Probando $file ..."
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp -TimeoutSec 120
            if ((Get-Item $tmp).Length -lt 1MB) { throw "descarga incompleta" }
            $downloaded = $true
            Write-Host "Descargado: $url"
            break
        } catch {
            Write-Host "  (no disponible: $($_.Exception.Message))"
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
    if (-not $downloaded) {
        Write-Host "ERROR: no se encontro un Expert Bundle de Windows disponible." -ForegroundColor Red
        exit 1
    }

    Write-Host "Extrayendo..."
    tar -xzf $tmp -C $TorDir
    Remove-Item $tmp -ErrorAction SilentlyContinue

    # the bundle unpacks to <dir>/tor/tor.exe ; move its contents one level up
    $inner = Join-Path $TorDir "tor"
    if ((Test-Path $inner) -and -not (Test-Path $TorExe)) {
        Get-ChildItem $inner | Move-Item -Destination $TorDir -Force
        Remove-Item $inner -Force -Recurse -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $TorExe)) {
        Write-Host "ERROR: tor.exe no se encontro tras la extraccion." -ForegroundColor Red
        exit 1
    }
    Write-Host "Tor instalado en $TorDir"
} else {
    Write-Host "Tor ya esta instalado."
}

$running = Get-Process tor -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Tor ya esta corriendo (pid $($running.Id))."
} else {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    @"
SOCKSPort $SocksPort
DataDirectory $DataDir
Log notice file $LogFile
ExitNodes {ar}
StrictNodes 0
"@ | Set-Content -Path $Torrc -Encoding ASCII

    Write-Host "Arrancando Tor..."
    Start-Process -FilePath $TorExe -ArgumentList "-f", "`"$Torrc`"" -WindowStyle Hidden -PassThru | Out-Null
    Start-Sleep -Seconds 8
}

$probe = Test-NetConnection -ComputerName 127.0.0.1 -Port $SocksPort -WarningAction SilentlyContinue
if ($probe.TcpTestSucceeded) {
    Write-Host "TOR LISTO: socks5://127.0.0.1:$SocksPort"
    Write-Host ""
    Write-Host "Ejemplos:"
    Write-Host "  .\netscanner.exe -c 203.0.113.0/24 -p 80,443,554 -w 20 -t 5000 -o anon.jsonl --proxy socks5://127.0.0.1:$SocksPort"
    Write-Host "  .\scan-isp.ps1 -Proxy socks5://127.0.0.1:$SocksPort"
} else {
    Write-Host "ERROR: Tor no responde en el puerto $SocksPort. Revisa $LogFile" -ForegroundColor Red
    exit 1
}
