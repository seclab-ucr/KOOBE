echo ==^> Installing updates

set DISK=d:\

:: Install .net for WinXP
ver | find "5.1" > nul
if not %ERRORLEVEL% == 0 goto notxp
::%DISK%\dotNetFx40_Full_x86_x64.exe /q /norestart
::128 == never reboot
start /wait rundll32.exe setupapi,InstallHinfSection netfx40 128 c:\windows\inf\netfx40.inf
goto end

:notxp

if exist "%SystemDrive%\Program Files (x86)" (
    set UPDATES_DIR=%DISK%\win7_updates\x64
    set ARCH=x64
) else (
    set UPDATES_DIR=%DISK%\win7_updates\x86
    set ARCH=x86
)

:: Install .net (All OS >= 7)
echo Installing %UPDATES_DIR%\30_2019-11-09_ndp48-x86-x64-allos-enu.exe
%UPDATES_DIR%\30_2019-11-09_ndp48-x86-x64-allos-enu.exe /q /norestart

:: Apply updates for Windows 7
ver | find "6.1" > nul
if not %ERRORLEVEL% == 0 goto not7

echo Installing %UPDATES_DIR%\30_2020-01-09_NDP48-kb4532941-%ARCH%.exe
%UPDATES_DIR%\30_2020-01-09_NDP48-kb4532941-%ARCH%.exe /q /norestart

:: Install .net updates
for %%f in (%UPDATES_DIR%\06*.msu) do (
    echo Installing %%f
    start /wait wusa.exe %%f /quiet /norestart
)

:not7

:end
shutdown /r /t 0
