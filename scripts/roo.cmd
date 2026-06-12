@echo off
REM Windows/PowerShell shim -> the cross-platform Python CLI.
REM `scripts\roo run nmap ...` (or `roo ...` if scripts\ is on PATH) works from
REM PowerShell and cmd. Requires Python 3 and Docker Desktop on PATH.
where py >nul 2>nul && (py -3 "%~dp0roo.py" %*) || (python "%~dp0roo.py" %*)
