@echo off
rem pornire.bat -- lanseaza aplicatia web "Inventar statii AD" pentru testeri.
rem Nu foloseste diacritice in mesaje (fereastra cmd clasica le poate afisa gresit
rem in functie de codepage) -- vezi CITESTE-MA.txt pentru instructiuni complete.

setlocal enabledelayedexpansion
cd /d "%~dp0"
title Inventar statii AD

echo ============================================================
echo   Inventar statii AD - pornire
echo ============================================================
echo.

set "PYEXE="

rem Preferam Python 3.11, apoi 3.14, lansat prin "py launcher": instalarea
rem de mai jos poate fi 100%% offline, direct din vendor_wheels\ (pachetele de
rem acolo sunt precompilate pentru Python 3.11 si 3.14, Windows 64-bit).
where py >nul 2>nul
if !errorlevel! equ 0 (
    py -3.11 -c "1" >nul 2>nul
    if !errorlevel! equ 0 set "PYEXE=py -3.11"
    if not defined PYEXE (
        py -3.14 -c "1" >nul 2>nul
        if !errorlevel! equ 0 set "PYEXE=py -3.14"
    )
)

rem Daca nu exista py -3.11 / -3.14, folosim orice "python" gasit pe PATH -- prima
rem instalare va avea nevoie atunci de internet (vezi pasul urmator).
if not defined PYEXE (
    where python >nul 2>nul
    if !errorlevel! equ 0 set "PYEXE=python"
)
if not defined PYEXE (
    where py >nul 2>nul
    if !errorlevel! equ 0 set "PYEXE=py"
)

if not defined PYEXE (
    echo [EROARE] Nu am gasit Python instalat pe acest calculator.
    echo.
    echo Instaleaza Python de pe https://www.python.org/downloads/
    echo   - bifeaza "Add python.exe to PATH" la instalare
    echo   - recomandat: Python 3.11 sau 3.14 ^(64-bit^), ca instalarea pachetelor
    echo     sa mearga complet offline, din folderul vendor_wheels
    echo.
    echo Apoi ruleaza din nou acest fisier.
    echo.
    pause
    exit /b 1
)

echo Folosesc: !PYEXE!
echo.

rem Un "venv" copiat de pe alt calculator (ex. din ZIP) nu merge: pyvenv.cfg
rem indica spre un Python care nu exista aici. Daca nu porneste, il stergem
rem si il recream mai jos cu Python-ul de pe acest calculator.
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe -c "1" >nul 2>nul
    if !errorlevel! neq 0 (
        echo Mediul "venv" existent nu functioneaza pe acest calculator - il recreez...
        rmdir /s /q venv
    )
)

if not exist "venv\Scripts\python.exe" (
    echo Creez mediul Python local ^("venv"^), o singura data...
    !PYEXE! -m venv venv
    if !errorlevel! neq 0 (
        echo [EROARE] Crearea mediului "venv" a esuat.
        pause
        exit /b 1
    )
    echo.
)

echo Verific/instalez pachetele necesare ^(offline, din vendor_wheels^)...
venv\Scripts\python.exe -m pip install --no-index --find-links vendor_wheels -r requirements.txt --quiet
if !errorlevel! neq 0 (
    echo   Instalarea offline nu a mers ^(probabil alta versiune de Python^) --
    echo   incerc sa descarc pachetele din internet...
    venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
    if !errorlevel! neq 0 (
        echo.
        echo [EROARE] Nu am putut instala pachetele necesare.
        echo Verifica fie conexiunea la internet, fie foloseste Python 3.11
        echo sau 3.14, 64-bit ^(pentru instalarea offline din vendor_wheels^).
        echo.
        pause
        exit /b 1
    )
)
echo.

echo Pregatesc baza de date locala ^(o creez daca lipseste, o actualizez daca exista^)...
venv\Scripts\python.exe app\db.py
if !errorlevel! neq 0 (
    echo [EROARE] Initializarea bazei de date a esuat.
    pause
    exit /b 1
)
echo.

echo ------------------------------------------------------------
echo Pornesc aplicatia. Peste cateva secunde se deschide singura
echo in browser, la adresa:
echo.
echo     http://localhost:5057
echo.
echo NU inchide aceasta fereastra cat timp folosesti aplicatia --
echo inchiderea ei opreste serverul. Pentru oprire controlata,
echo apasa CTRL+C in aceasta fereastra.
echo ------------------------------------------------------------
echo.

start "" cmd /c "timeout /t 2 >nul & start http://localhost:5057"

venv\Scripts\python.exe app\webapp.py

echo.
echo Serverul s-a oprit.
pause
