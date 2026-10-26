@echo off
rem Build the ghidra-fleet virtualenv (Windows):
rem   - fastmcp from PyPI
rem   - pyghidra + jpype1 from the wheels bundled with the local Ghidra install
rem     (version-matched by design; do NOT mix with PyPI pyghidra)
rem Usage:
rem   scripts\setup_env.bat <GHIDRA_INSTALL_DIR>
rem   (or set GHIDRA_INSTALL_DIR in the environment first)
setlocal enabledelayedexpansion
cd /d "%~dp0.."

if "%GHIDRA_INSTALL_DIR%"=="" (
    if not "%~1"=="" (
        set "GHIDRA_INSTALL_DIR=%~1"
    ) else (
        echo [ERROR] GHIDRA_INSTALL_DIR not set.
        echo         Usage: scripts\setup_env.bat ^<path-to-ghidra-install^>
        exit /b 1
    )
)
set "DIST=%GHIDRA_INSTALL_DIR%\Ghidra\Features\PyGhidra\pypkg\dist"

if not exist "%DIST%" (
    echo [ERROR] PyGhidra dist not found: %DIST%
    echo         Is "%GHIDRA_INSTALL_DIR%" really a Ghidra install dir?
    exit /b 1
)

if not exist .venv (
    python -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat

python -m pip install --upgrade pip || exit /b 1
python -m pip install fastmcp || exit /b 1

for /f %%f in ('dir /b /a-d "%DIST%\pyghidra-*.whl" 2^>nul') do set "PYGHIDRA_WHEEL=%%f"
if not defined PYGHIDRA_WHEEL (
    echo [ERROR] no pyghidra wheel found in %DIST%
    exit /b 1
)
python -m pip install "%DIST%\%PYGHIDRA_WHEEL%" --no-deps || exit /b 1
python -m pip install packaging || exit /b 1

rem pyghidra pins Jpype1==x.y.z; the bundled wheel set may not cover every
rem Python version - fall back to PyPI jpype1 when this tag/platform is missing.
for /f %%i in ('python -c "import sys;print(f\"cp{sys.version_info[0]}{sys.version_info[1]}\")"') do set PYTAG=%%i
set "JPYPE_WHEEL="
for /f %%f in ('dir /b /a-d "%DIST%\jpype1-*-%PYTAG%-%PYTAG%-*.whl" 2^>nul') do set "JPYPE_WHEEL=%%f"
if defined JPYPE_WHEEL (
    python -m pip install "%DIST%\%JPYPE_WHEEL%" || exit /b 1
) else (
    echo bundled jpype1 has no %PYTAG% wheel - installing latest jpype1 from PyPI
    python -m pip install jpype1 || exit /b 1
)

python -m pip install -e . --no-deps || exit /b 1

echo.
echo [OK] ghidra-fleet env ready. Test:
echo   GHIDRA_INSTALL_DIR=%GHIDRA_INSTALL_DIR% .venv\Scripts\python -m ghidra_fleet
endlocal
