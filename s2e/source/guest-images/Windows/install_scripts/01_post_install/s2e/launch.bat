timeout 5

cd c:\s2e

:: ###########################################################################
:: This is used during installation
if exist d:\launch.bat (
    cmd /c d:\launch.bat > com1 2>&1
    exit
)

:: Sometimes, we need two install disks
if exist e:\launch.bat (
    cmd /c e:\launch.bat > com1 2>&1
    exit
)

cmd /c c:\s2e\snapshot.bat
