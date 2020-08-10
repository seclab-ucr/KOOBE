echo ==^> Setting up startup item

REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "s2e launcher" /t REG_SZ /F /D "cmd /C c:\s2e\launch.bat"
