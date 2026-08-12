# Detecta la red local real y escribe su CIDR /24 en la salida.
# Sin IPs grabadas: usa las interfaces de la maquina, priorizando
# la WiFi/LAN clasica (192.168.x) sobre las demas.
$ErrorActionPreference = "SilentlyContinue"

$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.AddressState -eq "Preferred" -and
    $_.IPAddress -notlike "169.254*" -and
    $_.IPAddress -notlike "127.*"
}

$pick = $ips | Where-Object { $_.IPAddress -like "192.168.*" } | Select-Object -First 1
if (-not $pick) {
    $pick = $ips | Where-Object { $_.IPAddress -like "10.*" } | Select-Object -First 1
}
if (-not $pick) {
    $pick = $ips | Where-Object { $_.IPAddress -like "172.*" } | Select-Object -First 1
}
if (-not $pick) {
    $pick = $ips | Select-Object -First 1
}

if ($pick) {
    $cidr = (($pick.IPAddress -split "\.")[0..2] -join ".") + ".0/24"
    if ($cidr -match "^(\d{1,3}\.){3}0/24$") {
        Write-Output $cidr
        exit 0
    }
}
exit 1