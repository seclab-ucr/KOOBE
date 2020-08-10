:: This file is executed when base image installation is completed
:: and before the system is rebooted in TCG mode


:: Build the global assembly cache so that it doesn't happen during
:: symbolic execution, which will severely degrade performance
:: to the point of making the system unusable.
c:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe executequeueditems

if exist "%SystemDrive%\Program Files (x86)" (
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe executequeueditems
)

timeout 60
shutdown /r /t 0
