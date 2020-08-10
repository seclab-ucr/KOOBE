:: This file is executed when base image installation is completed (in tcg mode)

:: Wait until all ngen instances completed
:wait
timeout 5
tasklist /fi "imagename eq ngen.exe" 2>&1 | find ":" > nul
if "%ERRORLEVEL%"=="1" goto wait

timeout 60
shutdown /r /t 0
