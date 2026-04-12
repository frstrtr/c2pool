; c2pool Windows Installer — Inno Setup Script
;
; Usage:
;   1. Build c2pool.exe and prepare the package directory (see PACKAGE_DIR below)
;   2. Set PACKAGE_DIR and VCREDIST_PATH below to match your build environment
;   3. Compile: "C:\...\Inno Setup 6\ISCC.exe" c2pool-setup.iss
;
; The package directory should contain:
;   c2pool.exe, start.bat, lib\*, web-static\*, explorer\*, config\*

; ── Configurable paths ──────────────────────────────────────────────────────
; Override on ISCC command line: /DPACKAGE_DIR=C:\path\to\package
#ifndef PACKAGE_DIR
  #define PACKAGE_DIR "C:\c2pool-package"
#endif
#ifndef VCREDIST_PATH
  #define VCREDIST_PATH "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Redist\MSVC\v143\vc_redist.x64.exe"
#endif

; ── App metadata ────────────────────────────────────────────────────────────
#define MyAppName "c2pool"
#define MyAppVersion "0.1.1-alpha"
#define MyAppPublisher "frstrtr"
#define MyAppURL "https://github.com/frstrtr/c2pool"
#define MyAppExeName "c2pool.exe"

[Setup]
AppId={{C2POOL-MINING-POOL}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\c2pool
DefaultGroupName=c2pool
OutputBaseFilename=c2pool-{#MyAppVersion}-windows-x86_64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Main binary
Source: "{#PACKAGE_DIR}\c2pool.exe"; DestDir: "{app}"; Flags: ignoreversion
; DLLs (secp256k1, etc.) — must be next to c2pool.exe for Windows DLL search
Source: "{#PACKAGE_DIR}\lib\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Web dashboard
Source: "{#PACKAGE_DIR}\web-static\*"; DestDir: "{app}\web-static"; Flags: ignoreversion recursesubdirs createallsubdirs
; Block explorer
Source: "{#PACKAGE_DIR}\explorer\*"; DestDir: "{app}\explorer"; Flags: ignoreversion recursesubdirs createallsubdirs
; Config examples
Source: "{#PACKAGE_DIR}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
; Start script
Source: "{#PACKAGE_DIR}\start.bat"; DestDir: "{app}"; Flags: ignoreversion
; VC++ Redistributable (installed silently, deleted after)
Source: "{#VCREDIST_PATH}"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\c2pool"; Filename: "{app}\c2pool.exe"; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""; WorkingDir: "{app}"
Name: "{group}\c2pool (start.bat)"; Filename: "{app}\start.bat"; WorkingDir: "{app}"
Name: "{group}\Uninstall c2pool"; Filename: "{uninstallexe}"
Name: "{commondesktop}\c2pool"; Filename: "{app}\c2pool.exe"; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""; WorkingDir: "{app}"

[Run]
; Install VC++ Runtime (skip if already present)
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing Visual C++ Runtime..."; Flags: waituntilterminated
; Offer to launch after install
Filename: "{app}\c2pool.exe"; Description: "Launch c2pool"; Flags: nowait postinstall skipifsilent; Parameters: "--integrated --net litecoin --dashboard-dir ""{app}\web-static"""

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
