; c2wallet-qt-signer Windows installer - Inno Setup script
;
; A separate script from c2pool-setup.iss ON PURPOSE: the node installer opens
; sharechain / stratum / dashboard / coin-P2P firewall ports, which is exactly
; what an offline signer must never ask for. This one adds NO firewall rule,
; passes NO launch parameters, installs per user without administrator rights,
; and leaves the post-install launch box unticked.
;
; Usage (release.yml c2wallet-windows job):
;   ISCC.exe c2wallet-qt-setup.iss ^
;     /DPACKAGE_DIR=C:\path\to\c2wallet-qt-signer-0.2.9-windows-x86_64 ^
;     /DMyAppVersion=0.2.9 ^
;     /DVCREDIST_PATH=C:\...\vc_redist.x64.exe ^
;     /DOutputBase=c2wallet-qt-signer-0.2.9-windows-x86_64-setup
;
; PACKAGE_DIR is the windeployqt tree: c2wallet-qt-signer.exe, the Qt DLLs and
; plugin folders, libsecp256k1-*.dll, licenses\, README-SIGNER.txt and
; MANIFEST.txt. Every file in it is installed as-is.
;
; VCREDIST_PATH is optional, with the same guard as c2pool-setup.iss: when it
; is empty or not a file, setup.exe is built without it and only checks
; whether the runtime is installed. When bundled, it runs only if the runtime
; is missing; that one step asks for elevation (vc_redist needs it).

#ifndef PACKAGE_DIR
  #define PACKAGE_DIR "C:\c2wallet-qt-package"
#endif
#ifndef VCREDIST_PATH
  #define VCREDIST_PATH ""
#endif
#if VCREDIST_PATH != "" && FileExists(VCREDIST_PATH)
  #define BundleVcRedist
#else
  #pragma warning "c2wallet-qt-setup: VC++ runtime NOT bundled (VCREDIST_PATH is empty or not a file: '" + VCREDIST_PATH + "')."
#endif

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef OutputBase
  #define OutputBase "c2wallet-qt-signer-" + MyAppVersion + "-windows-x86_64-setup"
#endif
#define MyAppName "c2wallet-qt-signer"
#define MyAppExeName "c2wallet-qt-signer.exe"
#define MyAppPublisher "frstrtr"
#define MyAppURL "https://github.com/frstrtr/c2pool"

[Setup]
AppId={{C2WALLET-QT-SIGNER}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\c2wallet-qt
DefaultGroupName=c2wallet-qt
DisableProgramGroupPage=yes
OutputBaseFilename={#OutputBase}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#PACKAGE_DIR}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#ifdef BundleVcRedist
Source: "{#VCREDIST_PATH}"; DestDir: "{tmp}"; DestName: "vc_redist.x64.exe"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\c2wallet-qt signer"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\README-SIGNER"; Filename: "{app}\README-SIGNER.txt"
Name: "{group}\Uninstall c2wallet-qt signer"; Filename: "{uninstallexe}"

[Run]
#ifdef BundleVcRedist
; Only when the runtime is missing; shellexec so Windows can ask for elevation.
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing the Visual C++ runtime..."; Check: not VcRuntimeInstalled; Flags: shellexec waituntilterminated skipifdoesntexist
#endif
; Offered, never ticked by default.
Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Description: "Launch c2wallet-qt signer"; Flags: nowait postinstall skipifsilent unchecked

[Code]
// The exe links the MSVC runtime dynamically (the Qt build's /MD), so it does
// not start without it. The redistributable registers in either registry view
// depending on its version, so both are read.
function RuntimeFlag(RootKey: Integer): Boolean;
var
  Installed: Cardinal;
begin
  Installed := 0;
  Result := RegQueryDWordValue(RootKey, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1);
end;

function VcRuntimeInstalled: Boolean;
begin
  Result := RuntimeFlag(HKLM64) or RuntimeFlag(HKLM32);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and (not VcRuntimeInstalled) then
    SuppressibleMsgBox('The Microsoft Visual C++ 2015-2022 Redistributable (x64) is not installed.' + #13#10#13#10 +
      'c2wallet-qt-signer needs it to start. Copy it to this machine and run it:' + #13#10 +
      'https://aka.ms/vs/17/release/vc_redist.x64.exe', mbInformation, MB_OK, IDOK);
end;
