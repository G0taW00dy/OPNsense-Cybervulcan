; Inno Setup script for OPNsense Cybervulcan (Windows tray app).
; Built by .github/workflows/build.yml:
;   iscc /DAppVersion=1.0.0 /DSourceDir=..\build\windows\x64\runner\Release installer\cybervulcan.iss
; Per-user install, no admin rights needed.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\windows\x64\runner\Release"
#endif

#define AppName "OPNsense Cybervulcan"
#define AppExe "Cybervulcan.exe"
; Must match windowsAppUserModelId in lib/src/platform/notifications.dart.
#define AppUserModelId "Cybervulcan.OPNsenseCybervulcan"

[Setup]
AppId={{B6C2A7F1-5E3D-4C1A-9F2B-7D8E0A1C3B55}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Cybervulcan
AppPublisherURL=https://github.com/G0taW00dy/opnsense-cybervulcan
DefaultDirName={autopf}\Cybervulcan
DefaultGroupName=Cybervulcan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=Cybervulcan-Setup-{#AppVersion}
SetupIconFile=cybervulcan.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Ask to close a running copy (the app holds this mutex).
AppMutex=Local\CybervulcanSingleInstance
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start Cybervulcan in the tray when I sign in"; GroupDescription: "Startup:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; The AppUserModelID on the Start-menu shortcut is what makes Windows show
; "Cybervulcan" (not "Windows PowerShell") as the notification sender.
Name: "{group}\Cybervulcan"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppUserModelId}"
Name: "{autodesktop}\Cybervulcan"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppUserModelId}"; Tasks: desktopicon

[Registry]
; Display name + icon for toast notifications from this AppUserModelID.
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\{#AppUserModelId}"; ValueType: string; ValueName: "DisplayName"; ValueData: "Cybervulcan"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\{#AppUserModelId}"; ValueType: string; ValueName: "IconUri"; ValueData: "{app}\data\flutter_assets\assets\icons\logo_512.png"
; Tray autostart (hidden window).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Cybervulcan"; ValueData: """{app}\{#AppExe}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch Cybervulcan"; Flags: nowait postinstall skipifsilent
; In-app updates run the installer with /SILENT: reopen the app afterwards.
Filename: "{app}\{#AppExe}"; Flags: nowait; Check: WizardSilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM {#AppExe} /F"; Flags: runhidden; RunOnceId: "KillCybervulcan"
