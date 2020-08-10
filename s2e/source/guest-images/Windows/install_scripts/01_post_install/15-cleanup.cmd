title Configuring system. Please wait...

echo ==^> Setting resolution
copy d:\resolution.exe %windir%\system32
resolution.exe 1024 768 24 0


:: Apply updates for Windows 10
ver | find "10.0" > nul
if not %ERRORLEVEL% == 0 goto not10

PowerShell.exe -ExecutionPolicy Unrestricted -File Debloat-Windows-10\scripts\remove-default-apps.ps1
PowerShell.exe -ExecutionPolicy Unrestricted -File Debloat-Windows-10\scripts\experimental_unfuckery.ps1
PowerShell.exe -ExecutionPolicy Unrestricted -File Debloat-Windows-10\scripts\disable-services.ps1
PowerShell.exe -ExecutionPolicy Unrestricted -File Debloat-Windows-10\scripts\disable-windows-defender.ps1
PowerShell.exe -ExecutionPolicy Unrestricted -File Debloat-Windows-10\scripts\optimize-user-interface.ps1

:not10

echo Done installing updates

echo ==^> Increasing service startup timeout
:: This is required when testing C# services that take a lot of time to start in S2E
:: By default, the system kills them after 30s. We increase this to 300s here.
reg add HKLM\SYSTEM\CurrentControlSet\Control /v ServicesPipeTimeout /t REG_DWORD /d 300000 /f

echo ==^> Turning off User Account Control (UAC)
:: see http://www.howtogeek.com/howto/windows-vista/enable-or-disable-uac-from-the-windows-vista-command-line/
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

echo ==^> Disabling action center notifications
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 0x1 /f

echo ==^> Disabling Windows Security service
sc config wscsvc start= disabled

echo ==^> Disabling Windows Defender
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0x1 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 0x0 /f

reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0x1 /f

 echo ==^> Disabling Windows Defender Realtime Protection
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0x1 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v ForceUpdateFromMU /t REG_DWORD /d 0x0 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v UpdateOnStartUp /t REG_DWORD /d 0x0 /f

echo ==^> Turning off driver signature enforcement (test signing)
Bcdedit.exe -set TESTSIGNING ON

echo ==^> Disabling new network prompt
REG ADD "HKLM\System\CurrentControlSet\Control\Network\NewNetworkWindowOff"

echo ==^> Turning off Program Compatibility Service
sc config pcasvc start= disabled

echo ==^> Turning off screen saver
REG ADD "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f

echo ==^> Optimizing for performance
REG ADD "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
regedit.exe /S max_perf.reg

echo ==^> Turning off fast boot
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f

echo ==^> Disabling USB
sc config usbstor start= disabled

echo ==^> Turning off System Restore
:: see http://www.windows-commandline.com/enable-disable-system-restore-service/
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f

echo ==^> Turning off System Restore Service
sc config srservice start= disabled

echo ==^> Turning off pagefile
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset delete

echo ==^> Password never expires
wmic path Win32_UserAccount where Name='s2e' set PasswordExpires=false

echo ==^> Setting power configuration to High Performance
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
echo ==^> Turning off monitor timeout
powercfg -Change -monitor-timeout-ac 0
powercfg -Change -monitor-timeout-dc 0

echo ==^> Turning off hibernation
powercfg -h off

echo ==^> Disable windows balloon tips
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableBalloonTips /t REG_DWORD /d 0 /f

echo ==^> Disabling extra services

rem These are in winxp
sc config HelpSvc start= disabled
sc config Nla start= disabled
sc config RemoteRegistry start= disabled
sc config Schedule start= disabled
sc config SharedAccess start= disabled
sc config wzcsvc start= disabled


sc config AeLookupSvc start= disabled
sc config UxSms start= disabled
sc config DPS start= disabled
sc config WdiServiceHost start= disabled
sc config WdiSystemHost start= disabled
sc config TrkWks start= disabled
sc config iphlpsvc start= disabled
sc config CscService start= disabled
sc config LanmanServer start= disabled
sc config LanmanWorkstation start= disabled
sc config lmhosts start= disabled
sc config Themes start= disabled
sc config WPDBusEnum start= disabled
sc config Spooler start= disabled
sc config AudioSrv start= disabled
sc config AudioEndpointBuilder start= disabled
sc config WSearch start= disabled

sc config CryptSvc start= demand

sc config AppMgmt start= disabled
sc config PeerDistSvc start= disabled
sc config WPCSvc start= disabled
sc config MSiSCSI start= disabled
sc config napagent start= disabled
sc config RpcLocator start= disabled
sc config SCPolicySvc start= disabled
sc config SNMPTRAP start= disabled
sc config StorSvc start= disabled
sc config WbioSrvc start= disabled
sc config wcncsvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config Browser start= disabled
sc config SstpSvc start= disabled
sc config SSDPSRV start= disabled
sc config upnphost start= disabled
sc config NcdAutoSetup start= disabled
sc config WinHttpAutoProxySvc start= disabled

sc config BthServ start= disabled

sc config MSDTC start= disabled

sc config EapHost start= demand
sc config fdPHost start= disabled
sc config FDResPub start= demand
sc config hidserv start= demand
sc config KtmRm start= disabled
sc config ProtectedStorage start= disabled
sc config TabletInputService start= disabled
sc config VSS start= disabled
sc config WebClient start= disabled
sc config WerSvc start= disabled
sc config MpsSvc start= disabled
sc config stisvc start= demand

sc config wscsvc start= disabled
sc config pcasvc start= disabled
sc config usbstor start= disabled

sc config srservice start= disabled

echo ==^> Disabling Windows Defender
sc config WinDefend start= disabled
