; c2pool Windows Installer — Inno Setup Script
;
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

[Setup]
AppId={{C2POOL-MINING-POOL}
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
; VC++ Redistributable (installed silently, deleted after)
Source: "{#VCREDIST_PATH}"; DestDir: "{tmp}"; Flags: deleteafterinstall skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""; WorkingDir: "{app}"
Name: "{group}\{#MyAppName} (start.bat)"; Filename: "{app}\start.bat"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""; WorkingDir: "{app}"

[Run]
; Install VC++ Runtime (skip if already present)
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing Visual C++ Runtime..."; Flags: waituntilterminated skipifdoesntexist
; Offer to launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""

[Code]
var
  ResultCode: Integer;

procedure AddFirewallRule(RuleName: String; Port: String);
var
  Cmd: String;
begin
  Cmd := '/c netsh advfirewall firewall add rule name="' + RuleName + '" dir=in action=allow protocol=tcp localport=' + Port;
  Exec('cmd.exe', Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure DeleteFirewallRule(RuleName: String);
begin
  Exec('cmd.exe', '/c netsh advfirewall firewall delete rule name="' + RuleName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    AddFirewallRule('c2pool P2P Sharechain', '9326');
    AddFirewallRule('c2pool Stratum',        '9327');
    AddFirewallRule('c2pool Dashboard',      '8080');
    AddFirewallRule('c2pool LTC P2P',        '9333');
    AddFirewallRule('c2pool DOGE P2P',       '22556');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DeleteFirewallRule('c2pool P2P Sharechain');
    DeleteFirewallRule('c2pool Stratum');
    DeleteFirewallRule('c2pool Dashboard');
    DeleteFirewallRule('c2pool LTC P2P');
    DeleteFirewallRule('c2pool DOGE P2P');
  end;
end;
