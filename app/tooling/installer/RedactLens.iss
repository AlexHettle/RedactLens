#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#ifndef MyAppNumericVersion
  #define MyAppNumericVersion "0.1.0.0"
#endif
#ifndef MySourceDir
  #define MySourceDir "..\..\.artifacts\dist\RedactLens"
#endif
#ifndef MyOutputDir
  #define MyOutputDir "..\..\.artifacts\release"
#endif

[Setup]
AppId={{9A19339D-7851-4DA5-A889-E211DB4192B7}
AppName=RedactLens
AppVersion={#MyAppVersion}
AppVerName=RedactLens {#MyAppVersion}
AppPublisher=RedactLens
DefaultDirName={localappdata}\Programs\RedactLens
DefaultGroupName=RedactLens
UsePreviousAppDir=no
UsePreviousGroup=no
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#MyOutputDir}
OutputBaseFilename=RedactLens-Setup-{#MyAppVersion}-windows-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\assets\branding\redactlens.ico
WizardImageFile=..\..\assets\branding\redactlens-installer-wizard.png
WizardSmallImageFile=..\..\assets\branding\redactlens-icon.png
CloseApplications=force
CloseApplicationsFilter=RedactLens.exe,RedactScout.exe
RestartApplications=no
UsePreviousTasks=yes
UninstallDisplayIcon={app}\RedactLens.exe
VersionInfoVersion={#MyAppNumericVersion}
VersionInfoDescription=RedactLens installer
VersionInfoProductName=RedactLens
VersionInfoProductVersion={#MyAppVersion}

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\RedactLens.exe"
Type: files; Name: "{autodesktop}\RedactScout.lnk"
Type: filesandordirs; Name: "{userprograms}\RedactScout"

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\assets\branding\redactlens.ico"; DestDir: "{app}"; DestName: "RedactLens.ico"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Icons]
Name: "{group}\RedactLens"; Filename: "{app}\RedactLens.exe"; WorkingDir: "{app}"; IconFilename: "{app}\RedactLens.ico"; AppUserModelID: "RedactLens.Desktop"
Name: "{autodesktop}\RedactLens"; Filename: "{app}\RedactLens.exe"; WorkingDir: "{app}"; IconFilename: "{app}\RedactLens.ico"; AppUserModelID: "RedactLens.Desktop"; Tasks: desktopicon

[Run]
Filename: "{app}\RedactLens.exe"; Description: "Launch RedactLens"; Flags: nowait postinstall skipifsilent

[Code]
procedure RequestAppShutdown(ExecutablePath: String; SignalDirectory: String);
var
  Attempt: Integer;
  SignalFile: String;
begin
  if not FileExists(ExecutablePath) then
    exit;

  SignalFile := SignalDirectory + '\reinstall.shutdown';
  if not ForceDirectories(SignalDirectory) then
    exit;
  if not SaveStringToFile(SignalFile, 'reinstall', False) then
    exit;

  { Newer versions drain Uvicorn and remove this file when they finish. }
  { Older or unresponsive versions are handled by CloseApplications=force. }
  for Attempt := 1 to 30 do
  begin
    if not FileExists(SignalFile) then
      break;
    Sleep(100);
  end;
end;

procedure CleanupLegacyInstallation;
var
  LegacyDirectory: String;
begin
  LegacyDirectory := ExpandConstant('{localappdata}\Programs\RedactScout');
  DelTree(LegacyDirectory + '\_internal', True, True, True);
  DeleteFile(LegacyDirectory + '\RedactScout.exe');
  DeleteFile(LegacyDirectory + '\RedactScout.ico');
  DeleteFile(LegacyDirectory + '\LICENSE');
  DeleteFile(LegacyDirectory + '\THIRD_PARTY_NOTICES.md');
  DeleteFile(LegacyDirectory + '\unins000.exe');
  DeleteFile(LegacyDirectory + '\unins000.dat');
  DeleteFile(LegacyDirectory + '\unins000.msg');
  RemoveDir(LegacyDirectory);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  RequestAppShutdown(
    ExpandConstant('{app}\RedactLens.exe'),
    ExpandConstant('{localappdata}\RedactLens')
  );
  RequestAppShutdown(
    ExpandConstant('{localappdata}\Programs\RedactScout\RedactScout.exe'),
    ExpandConstant('{localappdata}\RedactScout')
  );
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    CleanupLegacyInstallation;
end;
