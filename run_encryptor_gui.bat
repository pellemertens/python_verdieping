@echo off
echo ====================================
echo Python Encryptor GUI Starter
echo ====================================

REM Stap 1: Haal de gebruikersnaam op
set "USERFOLDER=%USERPROFILE%"

REM Stap 2: Pad naar Downloads
set "DOWNLOADSPATH=%USERFOLDER%\Downloads"
set "SCRIPT=%DOWNLOADSPATH%\image_encryptor_gui.py"

REM Stap 3: Controleer pip
where pip >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo [FOUT] pip is niet gevonden. Zorg ervoor dat Python aan PATH is toegevoegd.
    pause
    exit /b
)

REM Stap 4: Installeer benodigde libraries
echo [INFO] Vereiste libraries worden geïnstalleerd...
pip install cryptography pillow >nul

IF %ERRORLEVEL% EQU 0 (
    echo [GELUKT] Libraries geïnstalleerd!
) ELSE (
    echo [FOUT] Installatie mislukt.
    pause
    exit /b
)

REM Stap 5: Controleer of script bestaat
if exist "%SCRIPT%" (
    echo [INFO] Script gevonden in Downloads. Start image_encryptor_gui.py...
    python "%SCRIPT%"
) ELSE (
    echo [FOUT] Het script 'image_encryptor_gui.py' is niet gevonden in Downloads.
    echo Plaats het bestand in de map: %DOWNLOADSPATH%
)

pause
