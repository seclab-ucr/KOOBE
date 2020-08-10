setlocal EnableDelayedExpansion EnableExtensions

echo ==^> Installing S2E guest tools

xcopy /E /H %~dp0\s2e c:\s2e\
