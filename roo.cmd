@echo off
REM Windows/PowerShell shim -> the cross-platform Python CLI.
REM `.\roo run nmap ...` (or `roo ...` if the repo root is on PATH) works from
REM PowerShell and cmd. Requires Python 3 and Docker Desktop on PATH.
where py >nul 2>nul && (py -3 "%~dp0scripts\roo.py" %*) || (python "%~dp0scripts\roo.py" %*)
