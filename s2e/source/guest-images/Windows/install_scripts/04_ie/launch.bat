echo ==^> Installing updates

set DISK=d:\

:: Apply updates for Windows 7
ver | find "6.1" > nul
if not %ERRORLEVEL% == 0 goto not7

if exist "%SystemDrive%\Program Files (x86)" (
    set UPDATES_DIR=%DISK%\win7_updates\x64
    set ARCH=x64
) else (
    set UPDATES_DIR=%DISK%\win7_updates\x86
    set ARCH=x86
)

:: Install IE
echo %UPDATES_DIR%\15_2013-11-06_IE11-Windows6.1-%ARCH%-en-us.exe
start /wait %UPDATES_DIR%\15_2013-11-06_IE11-Windows6.1-%ARCH%-en-us.exe /passive /quiet /norestart

for %%f in (%UPDATES_DIR%\15*.msu) do (
    echo Installing %%f
    start /wait wusa.exe %%f /quiet /norestart
)

:: Install silverlight
echo Installing %UPDATES_DIR%\30_2019-01-16_Silverlight-%ARCH%.exe
start /wait %UPDATES_DIR%\30_2019-01-16_Silverlight-%ARCH%.exe /q /norestart

:not7

shutdown /r /t 0
