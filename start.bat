@echo off
setlocal enabledelayedexpansion
set DIR=%~dp0
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=%DIR%config\c2pool_mainnet.yaml

:: Locate the packaged coin binary. release.yml packages it per-coin as
:: c2pool-<coin>.exe, so resolve by glob rather than a hard-coded name;
:: fall back to a plain c2pool.exe for source builds.
set BIN=
for %%f in ("%DIR%c2pool-*.exe") do set BIN=%%f
if "!BIN!"=="" if exist "%DIR%c2pool.exe" set BIN=%DIR%c2pool.exe
if "!BIN!"=="" (
    echo ERROR: no c2pool binary found in %DIR%
    exit /b 1
)
for %%f in ("!BIN!") do set BINNAME=%%~nxf

echo === !BINNAME! ===
echo Config:   %CONFIG%
echo Web:      http://0.0.0.0:8080
echo Explorer: http://0.0.0.0:9090

:: Start c2pool
start /B "" "!BIN!" --config "%CONFIG%" --dashboard-dir "%DIR%web-static"

:: Wait for API
:wait_loop
timeout /t 2 /nobreak >nul
curl -s -X POST -H "Content-Type: application/json" ^
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"getblockchaininfo\",\"params\":[],\"id\":1}" ^
    http://127.0.0.1:8080/ 2>nul | findstr "blocks" >nul
if errorlevel 1 goto wait_loop
echo c2pool ready.

:: Start explorer
where python3 >nul 2>&1
if not errorlevel 1 (
    start /B "" python3 "%DIR%explorer\explorer.py" ^
        --ltc-host 127.0.0.1 --ltc-port 8080 ^
        --ltc-user c2pool --ltc-pass c2pool ^
        --web-port 9090 --no-doge
    echo Explorer started on port 9090
) else (
    echo WARNING: python3 not found - explorer not started
)

:: Keep window open
pause
