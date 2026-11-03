@echo off
title AutoShield-EV - Autopilot EV Cybersecurity Operations Center
echo ====================================================================
echo   Launching AutoShield-EV: Autopilot Cybersecurity Operations Center
echo ====================================================================
echo.

if exist "%~dp0index.html" (
    set HTML_PATH=%~dp0index.html
) else if exist "%~dp0autopilot-ev-cybersec\index.html" (
    set HTML_PATH=%~dp0autopilot-ev-cybersec\index.html
) else (
    set HTML_PATH=%~dp0standalone_autoshield.html
)

:: Check for Microsoft Edge
where msedge >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting AutoShield-EV in Microsoft Edge App Mode...
    start msedge --app="file:///%HTML_PATH:\=/%" --window-size=1480,940 --user-data-dir="%TEMP%\AutoShield_Profile"
    goto END
)

:: Check for Google Chrome
where chrome >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting AutoShield-EV in Google Chrome App Mode...
    start chrome --app="file:///%HTML_PATH:\=/%" --window-size=1480,940 --user-data-dir="%TEMP%\AutoShield_Profile"
    goto END
)

:: Fallback to default web browser
echo Launching in default web browser...
start "" "%HTML_PATH%"

:END
echo.
echo AutoShield-EV Cybersecurity Center is running!
echo Access directly anytime via: %HTML_PATH%
