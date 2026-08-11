@echo off
chcp 65001 >nul
cd /d "%~dp0"

for /f "usebackq delims=" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detectar-red.ps1"`) do set RED=%%i

if "%RED%"=="" (
    echo No se pudo detectar la red local automaticamente.
    echo Escribila a mano en este comando (panel: abri Netscanner Panel - Nuevo escaneo):
    echo   netscanner.exe -c 192.168.1.0/24 -p 80,443,8080,8000,554,21,22,445,5000,9000,34567,37777,5001,139,135 -w 400 -t 600 -o casa.jsonl
    pause
    exit /b 1
)

echo [netscanner] escaneando tu red local (%RED%) con la lista completa de puertos...
netscanner.exe -c %RED% -p 80,443,8080,8000,554,21,22,445,5000,9000,34567,37777,5001,139,135 -w 400 -t 600 -o casa.jsonl
echo.
echo Listo. Abri el panel (Netscanner Panel) para ver los resultados.
pause