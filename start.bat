@echo off
setlocal DisableDelayedExpansion
rem c2pool start script for the Windows packages: launches the pool node and,
rem for the coins whose node serves the explorer API, the block explorer.
rem
rem One script ships in every per-coin package; the coin is taken from the
rem c2pool-<coin>.exe next to it. Each binary has its own command line
rem (src\c2pool\main_<coin>.cpp), the same one the setup.exe shortcuts use
rem (installer\windows\c2pool-setup.iss).
rem
rem Usage: start.bat [CONFIG] [EXTRA_ARGS...]
rem   CONFIG      YAML config file. Only c2pool-ltc reads one (--config); the
rem               default config\c2pool_mainnet.yaml is used only if it exists
rem               (copy it from config\c2pool_mainnet.yaml.example). Without it
rem               the node runs on its built-in defaults.
rem   EXTRA_ARGS  appended to the node command line, e.g.
rem               start.bat --node-owner-address YOUR_ADDRESS
rem Set C2POOL_DRY_RUN=1 to print the commands instead of running them.

rem The explorer helper re-runs this script in its own window (see :run).
if "%~1"=="__c2pool_explorer__" goto explorer_helper

set "DIR=%~dp0"
set "SELF=%~nx0"
set "SELF_FULL=%~f0"
set "WEB_PORT=8080"
set "EXPLORER_PORT=9090"

rem A first argument that is not a flag is the config file (back-compat).
set "CONFIG="
set "CONFIG_GIVEN=0"
set "ARG1=%~1"
if not defined ARG1 goto args_config_done
if "%ARG1:~0,1%"=="-" goto args_config_done
set "CONFIG=%~f1"
set "CONFIG_GIVEN=1"
shift
:args_config_done
if not defined CONFIG set "CONFIG=%DIR%config\c2pool_mainnet.yaml"

rem Remaining arguments go to the node; a web/stratum port among them wins.
set "EXTRA="
set "PREV="
set "WEB_PORT_OVR="
set "STRATUM_PORT_OVR="
:args_extra
if "%~1"=="" goto args_done
set "A=%~1"
if /i "%PREV%"=="--web-port" set "WEB_PORT_OVR=%A%"
if /i "%PREV%"=="--http-port" set "WEB_PORT_OVR=%A%"
if /i "%PREV%"=="--http" set "WEB_PORT_OVR=%A%"
if /i "%PREV%"=="--stratum" set "STRATUM_PORT_OVR=%A%"
if /i "%PREV%"=="--stratum-port" set "STRATUM_PORT_OVR=%A%"
if /i "%PREV%"=="--worker-port" set "STRATUM_PORT_OVR=%A%"
if /i "%PREV%"=="-w" set "STRATUM_PORT_OVR=%A%"
set "EXTRA=%EXTRA% %1"
set "PREV=%A%"
shift
goto args_extra
:args_done

rem Locate the packaged coin binary. release.yml packages it per-coin as
rem c2pool-<coin>.exe, so resolve by glob rather than a hard-coded name;
rem fall back to a plain c2pool.exe (the LTC dev alias) for source builds.
set "BIN="
for %%f in ("%DIR%c2pool-*.exe") do set "BIN=%%~ff"
if not defined BIN if exist "%DIR%c2pool.exe" set "BIN=%DIR%c2pool.exe"
if defined BIN goto have_bin
echo ERROR: no c2pool binary found in %DIR%
goto fail
:have_bin
for %%f in ("%BIN%") do set "BINNAME=%%~nxf"
set "COIN="
if /i "%BINNAME%"=="c2pool.exe" set "COIN=ltc"
if not defined COIN for /f "tokens=2 delims=-." %%c in ("%BINNAME%") do set "COIN=%%c"

set "DASHBOARD=%DIR%web-static"
set "USE_CONFIG=0"
if /i "%COIN%"=="ltc" goto coin_ltc
if /i "%COIN%"=="dash" goto coin_dash
if /i "%COIN%"=="btc" goto coin_btc
if /i "%COIN%"=="dgb" goto coin_dgb
if /i "%COIN%"=="bch" goto coin_bch
if /i "%COIN%"=="bip110" goto coin_bip110
echo ERROR: unknown coin "%COIN%" (binary %BINNAME%); run the binary directly (see --help).
goto fail

:coin_ltc
rem Integrated P2P pool with embedded LTC + DOGE SPV; Stratum 9327. The YAML
rem config, when present, is the source of truth (CLI flags would override
rem it), so only the dashboard dir is added to it.
set "STRATUM_PORT=9327"
if not exist "%CONFIG%" goto ltc_no_config
set "USE_CONFIG=1"
set NODE_ARGS=--config "%CONFIG%" --dashboard-dir "%DASHBOARD%"
goto coin_done
:ltc_no_config
set NODE_ARGS=--integrated --net litecoin --dashboard-dir "%DASHBOARD%"
goto coin_done

:coin_dash
rem A bare --run is daemonless (embedded serving + coin-peer discovery).
rem Dashboard is on at 8080 by default; Stratum is off unless bound.
set "STRATUM_PORT=7903"
set NODE_ARGS=--run --stratum 7903 --dashboard-dir "%DASHBOARD%"
goto coin_done

:coin_btc
rem Needs a coin source (--coin-p2p-discover or --bitcoind); Stratum and the
rem dashboard (cwd-relative web-static) are off unless bound.
set "STRATUM_PORT=9332"
set "NODE_ARGS=--coin-p2p-discover --stratum 9332 --http 8080"
goto coin_done

:coin_dgb
rem Without --run the binary runs its self-test and exits.
set "STRATUM_PORT=5025"
set "NODE_ARGS=--run --coin-p2p-discover --stratum 5025 --http 8080"
goto coin_done

:coin_bch
rem --pool is the pool run-loop; it needs --peer or --coin-p2p-discover.
set "STRATUM_PORT=9348"
set "NODE_ARGS=--pool --coin-p2p-discover --stratum 9348 --http 8080"
goto coin_done

:coin_bip110
rem Without --run the self-test runs and exits. --run discovers fork peers
rem by itself and binds Stratum on 9336 by default.
set "STRATUM_PORT=9336"
set "NODE_ARGS=--run --http 8080"
goto coin_done

:coin_done
if "%CONFIG_GIVEN%"=="0" goto config_checked
if /i not "%COIN%"=="ltc" goto config_ignored
if "%USE_CONFIG%"=="1" goto config_checked
echo ERROR: config file not found: %CONFIG%
goto fail
:config_ignored
echo WARNING: %BINNAME% does not read YAML config files; ignoring %CONFIG%.
echo          Pass options as flags instead, e.g. %SELF% --node-owner-address YOUR_ADDRESS
echo          (see %BINNAME% --help).
:config_checked

if "%USE_CONFIG%"=="0" goto config_ports_done
rem Coin-guard: v0.2.3 shipped the Litecoin config in every coin package, so
rem refuse a config whose first (header) line does not name the binary's coin.
findstr /n "^" "%CONFIG%" | findstr /b /c:"1:" | findstr /i /c:"%COIN%" >nul
if not errorlevel 1 goto guard_ok
echo ERROR: config/coin mismatch - binary is %BINNAME% but the header of
echo        %CONFIG% does not name %COIN%.
echo Launch with the coin-correct config, e.g.: %SELF% config\c2pool_mainnet.yaml
goto fail
:guard_ok
set "CFG_WEB="
set "CFG_STRATUM="
for /f "tokens=2" %%p in ('findstr /r /b /c:"web_port:" "%CONFIG%"') do if not defined CFG_WEB set "CFG_WEB=%%p"
for /f "tokens=2" %%p in ('findstr /r /b /c:"stratum_port:" "%CONFIG%"') do if not defined CFG_STRATUM set "CFG_STRATUM=%%p"
if defined CFG_WEB set "WEB_PORT=%CFG_WEB%"
if defined CFG_STRATUM set "STRATUM_PORT=%CFG_STRATUM%"
:config_ports_done
if defined WEB_PORT_OVR set "WEB_PORT=%WEB_PORT_OVR%"
if defined STRATUM_PORT_OVR set "STRATUM_PORT=%STRATUM_PORT_OVR%"
rem [HOST:]PORT -> PORT
for /f "tokens=2 delims=:" %%p in ("%WEB_PORT%") do set "WEB_PORT=%%p"
for /f "tokens=2 delims=:" %%p in ("%STRATUM_PORT%") do set "STRATUM_PORT=%%p"
set "EXPLORER_API=http://127.0.0.1:%WEB_PORT%/api/explorer"

rem Explorer: explorer.py reads the node's loopback /api/explorer surface.
rem c2pool-dash and c2pool-bip110 serve it by default, c2pool-ltc only with
rem "explorer: true" in its config; btc, dgb and bch do not serve it.
set "EXPLORER_ARGS="
set "EXPLORER_NOTE=not available for %BINNAME%, it has no explorer API"
if /i "%COIN%"=="ltc" goto explorer_ltc
if /i "%COIN%"=="dash" goto explorer_generic
if /i "%COIN%"=="bip110" goto explorer_generic
goto explorer_chosen
:explorer_ltc
set "EXPLORER_NOTE=off, set 'explorer: true' in the config to enable it"
if "%USE_CONFIG%"=="0" goto explorer_chosen
findstr /r /b /c:"explorer: *true" "%CONFIG%" >nul || goto explorer_chosen
set "EXPLORER_ARGS=--web-port %EXPLORER_PORT% --ltc-c2pool %EXPLORER_API% --doge-c2pool %EXPLORER_API%"
goto explorer_chosen
:explorer_generic
set "EXPLORER_ARGS=--coin %COIN% --c2pool %EXPLORER_API% --web-port %EXPLORER_PORT%"
:explorer_chosen

if not defined EXPLORER_ARGS goto python_done
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python3 >nul 2>&1 && set "PY=python3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if defined PY goto python_done
set "EXPLORER_ARGS="
set "EXPLORER_NOTE=not started, Python 3 not found (install it from python.org)"
:python_done

echo === %BINNAME% ===
if "%USE_CONFIG%"=="1" echo Config:   %CONFIG%
if "%USE_CONFIG%"=="0" echo Config:   none, built-in defaults
echo Web:      http://0.0.0.0:%WEB_PORT%
echo Stratum:  stratum+tcp://0.0.0.0:%STRATUM_PORT%
if defined EXPLORER_ARGS echo Explorer: http://0.0.0.0:%EXPLORER_PORT%, in a separate window
if not defined EXPLORER_ARGS echo Explorer: %EXPLORER_NOTE%
echo.

if not defined C2POOL_DRY_RUN goto run
echo node:     cd /d "%DIR%" ^&^& "%BIN%" %NODE_ARGS%%EXTRA%
if defined EXPLORER_ARGS echo explorer: %PY% "%DIR%explorer\explorer.py" %EXPLORER_ARGS%
exit /b 0

:run
rem btc, dgb, bch and bip110 serve the dashboard from a web-static directory
rem relative to the working directory.
cd /d "%DIR%"
rem The explorer waits for the node's API in its own minimized window, so the
rem node runs in this window, gets Ctrl-C and sets the exit code.
if defined EXPLORER_ARGS start "c2pool-%COIN% explorer" /min cmd /c ""%SELF_FULL%" __c2pool_explorer__"
"%BIN%" %NODE_ARGS%%EXTRA%
set "RC=%ERRORLEVEL%"
if defined EXPLORER_ARGS taskkill /fi "WINDOWTITLE eq c2pool-%COIN% explorer*" /t /f >nul 2>&1
echo.
echo %BINNAME% exited with code %RC%.
pause
exit /b %RC%

:fail
pause
exit /b 1

:explorer_helper
rem Runs in the explorer window with the environment of the launching script.
cd /d "%DIR%"
echo Waiting for the c2pool explorer API at %EXPLORER_API% ...
set /a TRIES=0
:explorer_wait
timeout /t 2 /nobreak >nul
tasklist /fi "imagename eq %BINNAME%" 2>nul | find /i "%BINNAME%" >nul || exit /b 0
where curl >nul 2>&1 || goto explorer_start
curl -s "%EXPLORER_API%/getblockchaininfo" 2>nul | findstr /c:blocks >nul && goto explorer_start
set /a TRIES+=1
if %TRIES% geq 120 goto explorer_start
goto explorer_wait
:explorer_start
%PY% "%DIR%explorer\explorer.py" %EXPLORER_ARGS%
exit /b 0
