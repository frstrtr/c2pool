; c2pool Windows Installer — Inno Setup Script
;
; One script builds the setup.exe for every coin binary.
; Usage:
;   1. Build c2pool-<coin>.exe and prepare the package directory (PACKAGE_DIR)
;   2. Compile, overriding the per-package defines on the ISCC command line:
;        ISCC.exe c2pool-setup.iss ^
;          /DPACKAGE_DIR=C:\path\to\c2pool-ltc-0.2.0-windows-x86_64 ^
;          /DVCREDIST_PATH=C:\...\vc_redist.x64.exe ^
;          /DMyAppName=c2pool-ltc /DMyAppVersion=0.2.0 ^
;          /DMyAppExeName=c2pool-ltc.exe ^
;          /DOutputBase=c2pool-ltc-0.2.0-windows-x86_64-setup
;
; MyAppName selects the coin: c2pool-ltc, c2pool-btc, c2pool-dgb, c2pool-dash,
; c2pool-bch or c2pool-bip110 (plain "c2pool" is the LTC dev alias). It picks
; the launch command line, the AppId and the firewall ports below.
;
; Optional overrides:
;   /DMyAppParams="..."  replaces the derived launch command line. The text is
;                        placed inside a double-quoted Inno Setup parameter, so
;                        a literal double quote must be written twice ("").
;   /DVCREDIST_PATH=...  the VC++ runtime installer to bundle. When it is empty
;                        or the file does not exist, setup.exe is still built
;                        without it (compiler warning) and setup only checks
;                        whether the runtime is already installed.
;
; The package directory should contain:
;   <exe>, start.bat, lib\*, web-static\*, explorer\*, config\*

; ── Configurable paths ──────────────────────────────────────────────────────
; Override on ISCC command line: /DPACKAGE_DIR=C:\path\to\package
#ifndef PACKAGE_DIR
  #define PACKAGE_DIR "C:\c2pool-package"
#endif
#ifndef VCREDIST_PATH
  #define VCREDIST_PATH "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Redist\MSVC\v143\vc_redist.x64.exe"
#endif

; Bundle the VC++ runtime only when VCREDIST_PATH names a file that exists.
; release.yml passes /DVCREDIST_PATH="%VCREDIST%", which is empty when its
; search finds nothing. An unguarded Source: "" makes ISCC abort with
; 'Parameter "Source" is empty' and no setup.exe is produced at all.
#if VCREDIST_PATH != "" && FileExists(VCREDIST_PATH)
  #define BundleVcRedist
#else
  #pragma warning "c2pool-setup: VC++ runtime NOT bundled (VCREDIST_PATH is empty or not a file: '" + VCREDIST_PATH + "'). The installer will only check for an installed runtime and tell the user where to get it."
#endif

; ── App metadata (all overridable via /D for per-coin packages) ─────────────
#ifndef MyAppName
  #define MyAppName "c2pool"
#endif
#ifndef MyAppVersion
  #define MyAppVersion "0.1.1-alpha"
#endif
#ifndef MyAppExeName
  #define MyAppExeName "c2pool.exe"
#endif
#ifndef OutputBase
  #define OutputBase "c2pool-" + MyAppVersion + "-windows-x86_64-setup"
#endif
#define MyAppPublisher "frstrtr"
#define MyAppURL "https://github.com/frstrtr/c2pool"

; ── Per-coin launch command line, AppId and firewall ports ─────────────────
; Every coin binary has its own argv parser (src/c2pool/main_<coin>.cpp).
; btc, dgb, bch and dash exit with "unknown argument" on a flag they do not
; know and bip110 silently ignores it, so one shared command line cannot
; work. The main shortcuts start the binary directly with WorkingDir={app}
; (no Python needed): btc, dgb, bch and bip110 serve the dashboard from
; "web-static" relative to the working directory (they have no
; --dashboard-dir flag). The "(start.bat)" shortcut runs the shipped launcher,
; which uses the same command lines and also starts the block explorer where
; the coin serves the explorer API. Keep these in sync with start.bat and
; start.sh.
;
; Ports: sharechain P2P, Stratum, dashboard (8080 everywhere) and the coin
; P2P port, from src/impl/<coin>/config_pool.hpp and params.hpp. Stratum and
; the dashboard are off by default on btc/dgb/bch (and the dashboard on
; bip110), so the command lines below bind Stratum on the p2pool worker port
; of each network and the dashboard on 8080.
#if MyAppName == "c2pool-ltc" || MyAppName == "c2pool"
; Integrated P2P pool, embedded LTC + DOGE SPV (main_ltc.cpp defaults).
; Stratum 9327 and dashboard 8080 are on by default.
  #define CoinParams '--integrated --net litecoin --dashboard-dir ""{app}\web-static""'
; Keep the AppId of the v0.1.x and v0.2.0 LTC installers so they upgrade in place.
  #define CoinAppId "{{C2POOL-MINING-POOL}"
  #define CoinTicker "LTC"
  #define FwSharechain "9326"
  #define FwStratum "9327"
  #define FwCoinP2P "9333"
  #define FwAuxTicker "DOGE"
  #define FwAuxP2P "22556"
  #define LegacyFirewallNames
#elif MyAppName == "c2pool-dash"
; A bare --run is the daemonless posture (embedded serving on, coin-P2P
; discovery implied). Dashboard is on at 8080 by default; Stratum is off
; unless bound, 7903 = PoolConfig::WORKER_PORT.
  #define CoinParams '--run --stratum 7903 --dashboard-dir ""{app}\web-static""'
  #define CoinAppId "{{C2POOL-MINING-POOL-DASH}"
  #define CoinTicker "DASH"
  #define FwSharechain "8999"
  #define FwStratum "7903"
  #define FwCoinP2P "9999"
#elif MyAppName == "c2pool-btc"
; Needs --coin-p2p-discover (or --bitcoind) or it prints usage and exits 1.
; Stratum 9332 = p2pool bitcoin WORKER_PORT.
  #define CoinParams '--coin-p2p-discover --stratum 9332 --http 8080'
  #define CoinAppId "{{C2POOL-MINING-POOL-BTC}"
  #define CoinTicker "BTC"
  #define FwSharechain "9333"
  #define FwStratum "9332"
  #define FwCoinP2P "8333"
#elif MyAppName == "c2pool-dgb"
; Without --run the binary runs its self-test and exits.
; Stratum 5025 = DGB worker_port (impl/dgb/params.hpp).
  #define CoinParams '--run --coin-p2p-discover --stratum 5025 --http 8080'
  #define CoinAppId "{{C2POOL-MINING-POOL-DGB}"
  #define CoinTicker "DGB"
  #define FwSharechain "5024"
  #define FwStratum "5025"
  #define FwCoinP2P "12024"
#elif MyAppName == "c2pool-bch"
; --pool is the pool run-loop (default is the ABLA self-test); it refuses to
; start without --peer or --coin-p2p-discover. Stratum 9348 = p2pool
; bitcoincash WORKER_PORT.
  #define CoinParams '--pool --coin-p2p-discover --stratum 9348 --http 8080'
  #define CoinAppId "{{C2POOL-MINING-POOL-BCH}"
  #define CoinTicker "BCH"
  #define FwSharechain "9349"
  #define FwStratum "9348"
  #define FwCoinP2P "8333"
#elif MyAppName == "c2pool-bip110"
; Without --run the KAT self-test runs and exits. --run turns on fork-peer
; discovery by itself and binds Stratum on 9336 by default.
  #define CoinParams '--run --http 8080'
  #define CoinAppId "{{C2POOL-MINING-POOL-BIP110}"
  #define CoinTicker "BIP110"
  #define FwSharechain "9337"
  #define FwStratum "9336"
  #define FwCoinP2P "8333"
#else
; Unknown coin: only usable with /DMyAppParams; of the firewall rules only
; the 8080 dashboard one is added.
  #define CoinParams ""
  #define CoinAppId "{{C2POOL-MINING-POOL-" + MyAppName + "}"
  #define CoinTicker ""
  #define FwSharechain ""
  #define FwStratum ""
  #define FwCoinP2P ""
  #pragma warning "c2pool-setup: unknown MyAppName '" + MyAppName + "': no default launch command line or firewall ports."
#endif

#ifdef MyAppParams
  #if MyAppParams != ""
    #define LaunchParams MyAppParams
  #endif
#endif
#ifndef LaunchParams
  #define LaunchParams CoinParams
#endif
#if LaunchParams == ""
  #error No launch command line for this MyAppName. Add a coin block to c2pool-setup.iss or pass /DMyAppParams.
#endif
#pragma message "c2pool-setup: " + MyAppName + " launches as: " + MyAppExeName + " " + LaunchParams

[Setup]
AppId={#CoinAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputBaseFilename={#OutputBase}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Main binary
Source: "{#PACKAGE_DIR}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; DLLs (secp256k1, etc.) — must be next to the exe for Windows DLL search
Source: "{#PACKAGE_DIR}\lib\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Web dashboard
Source: "{#PACKAGE_DIR}\web-static\*"; DestDir: "{app}\web-static"; Flags: ignoreversion recursesubdirs createallsubdirs
; Block explorer
Source: "{#PACKAGE_DIR}\explorer\*"; DestDir: "{app}\explorer"; Flags: ignoreversion recursesubdirs createallsubdirs
; Config examples
Source: "{#PACKAGE_DIR}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
; Start script
Source: "{#PACKAGE_DIR}\start.bat"; DestDir: "{app}"; Flags: ignoreversion
; Transition message blobs (authority-signed V36 upgrade signal)
Source: "{#PACKAGE_DIR}\transition_messages\*"; DestDir: "{app}\transition_messages"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
#ifdef BundleVcRedist
; VC++ Redistributable (installed silently, deleted after)
Source: "{#VCREDIST_PATH}"; DestDir: "{tmp}"; DestName: "vc_redist.x64.exe"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "{#LaunchParams}"; WorkingDir: "{app}"
Name: "{group}\{#MyAppName} (start.bat)"; Filename: "{app}\start.bat"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "{#LaunchParams}"; WorkingDir: "{app}"

[Run]
#ifdef BundleVcRedist
; Install VC++ Runtime (skip if already present)
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing Visual C++ Runtime..."; Flags: waituntilterminated skipifdoesntexist
#endif
; Offer to launch after install
Filename: "{app}\{#MyAppExeName}"; Parameters: "{#LaunchParams}"; WorkingDir: "{app}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
var
  ResultCode: Integer;

procedure DeleteFirewallRule(RuleName: String);
begin
  Exec('cmd.exe', '/c netsh advfirewall firewall delete rule name="' + RuleName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure AddFirewallRule(RuleName: String; Port: String);
var
  Cmd: String;
begin
  // netsh happily adds a second rule with the same name, so drop any rule
  // left by a previous install of this coin first.
  DeleteFirewallRule(RuleName);
  Cmd := '/c netsh advfirewall firewall add rule name="' + RuleName + '" dir=in action=allow protocol=tcp localport=' + Port;
  Exec('cmd.exe', Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Rule names carry the coin's app name so installing or uninstalling one coin
// never touches another coin's rules. An empty port means no rule.
procedure ApplyFirewallRule(Install: Boolean; RuleName: String; Port: String);
begin
  if Port = '' then
    Exit;
  if Install then
    AddFirewallRule(RuleName, Port)
  else
    DeleteFirewallRule(RuleName);
end;

procedure ApplyFirewallRules(Install: Boolean);
begin
  ApplyFirewallRule(Install, '{#MyAppName} P2P Sharechain', '{#FwSharechain}');
  ApplyFirewallRule(Install, '{#MyAppName} Stratum', '{#FwStratum}');
  ApplyFirewallRule(Install, '{#MyAppName} Dashboard', '8080');
  ApplyFirewallRule(Install, '{#MyAppName} {#CoinTicker} P2P', '{#FwCoinP2P}');
#ifdef FwAuxP2P
  ApplyFirewallRule(Install, '{#MyAppName} {#FwAuxTicker} P2P', '{#FwAuxP2P}');
#endif
end;

#ifndef BundleVcRedist
// The binaries link the MSVC runtime dynamically (ci/conan/windows-msvc.profile
// compiler.runtime=dynamic), so without it the exe does not start.
function VcRuntimeInstalled: Boolean;
var
  Installed: Cardinal;
begin
  Installed := 0;
  Result := RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1);
end;
#endif

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
#ifdef LegacyFirewallNames
    // v0.1.x / v0.2.0 LTC installers used these coin-less rule names.
    DeleteFirewallRule('c2pool P2P Sharechain');
    DeleteFirewallRule('c2pool Stratum');
    DeleteFirewallRule('c2pool Dashboard');
    DeleteFirewallRule('c2pool LTC P2P');
    DeleteFirewallRule('c2pool DOGE P2P');
#endif
    ApplyFirewallRules(True);
#ifndef BundleVcRedist
    if not VcRuntimeInstalled then
      SuppressibleMsgBox('The Microsoft Visual C++ 2015-2022 Redistributable (x64) was not found, and this installer does not include it.' + #13#10#13#10 +
        '{#MyAppName} needs it to start. Download and run:' + #13#10 +
        'https://aka.ms/vs/17/release/vc_redist.x64.exe', mbInformation, MB_OK, IDOK);
#endif
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    ApplyFirewallRules(False);
end;
