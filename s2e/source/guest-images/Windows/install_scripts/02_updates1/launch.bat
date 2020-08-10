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

for %%f in (%UPDATES_DIR%\02*.msu) do (
    echo Installing %%f
    start /wait wusa.exe %%f  /quiet /norestart
)

for %%f in (%UPDATES_DIR%\05*.msu) do (
    echo Installing %%f
    start /wait wusa.exe %%f  /quiet /norestart
)

:: Remove the end-of-life nagging screen
wusa /uninstall /kb:4493132 /quiet /norestart

:not7

shutdown /r /t 0
