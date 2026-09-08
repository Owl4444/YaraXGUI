@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run from the checkout, even when launched from another drive or directory.
set "YARAXGUI_BUILD_EXIT=1"
set "YARAXGUI_BUILD_IN_ROOT="
set "YARAXGUI_BUILD_PYTHON="
set "YARAXGUI_BUILD_PYTHON_ARGS="
set "YARAXGUI_BUILD_PROBE_VERBOSE="
set "YARAXGUI_BUILD_PROBE_EXIT="
set "YARAXGUI_BUILD_CANDIDATE="
pushd "%~dp0"
if errorlevel 1 goto directory_error
set "YARAXGUI_BUILD_IN_ROOT=1"

if not exist "requirements.txt" goto checkout_error
if not exist "packaging\yaraxgui.spec" goto checkout_error
if not exist "modules\yarax-editor\pyproject.toml" goto checkout_error

rem An explicit interpreter overrides automatic discovery.
if not "%~1"=="" goto explicit_python
if defined VIRTUAL_ENV call :try_python "%VIRTUAL_ENV%\Scripts\python.exe"
call :try_python "%CD%\.venv\Scripts\python.exe"
call :try_python "%CD%\venv\Scripts\python.exe"
for /d %%D in (".qtcreator\Python_*") do call :try_python "%%~fD\Scripts\python.exe"
call :try_python py -3.13
call :try_python py -3
call :try_python python
if not defined YARAXGUI_BUILD_PYTHON goto python_error
goto python_ready

:explicit_python
rem Keep the launcher selector, e.g. compile_to_exe.bat py -3.13.
rem An explicitly requested runtime must show its real error if unavailable.
set "YARAXGUI_BUILD_PROBE_VERBOSE=1"
call :try_python "%~1" %2
if not defined YARAXGUI_BUILD_PYTHON goto python_error

:python_ready
echo Using Python:
"%YARAXGUI_BUILD_PYTHON%" %YARAXGUI_BUILD_PYTHON_ARGS% -c "import sys; print(sys.executable); print(sys.version)"
echo.
echo Checking pip...
"%YARAXGUI_BUILD_PYTHON%" %YARAXGUI_BUILD_PYTHON_ARGS% -m pip --version >nul 2>&1
if not errorlevel 1 goto install_dependencies
"%YARAXGUI_BUILD_PYTHON%" %YARAXGUI_BUILD_PYTHON_ARGS% -m ensurepip --upgrade
set "YARAXGUI_BUILD_EXIT=%errorlevel%"
if not "%YARAXGUI_BUILD_EXIT%"=="0" goto dependency_error

:install_dependencies
echo Installing / refreshing dependencies...
"%YARAXGUI_BUILD_PYTHON%" %YARAXGUI_BUILD_PYTHON_ARGS% -m pip install -r requirements.txt
set "YARAXGUI_BUILD_EXIT=%errorlevel%"
if not "%YARAXGUI_BUILD_EXIT%"=="0" goto dependency_error

rem Do not kill running instances or delete the last executable before setup.
echo.
echo Building YaraXGUI executable...
echo Close any running copy of dist\YaraXGUI.exe before it is replaced.
"%YARAXGUI_BUILD_PYTHON%" %YARAXGUI_BUILD_PYTHON_ARGS% -m PyInstaller --clean --noconfirm packaging\yaraxgui.spec
set "YARAXGUI_BUILD_EXIT=%errorlevel%"
if not "%YARAXGUI_BUILD_EXIT%"=="0" goto build_error
echo.
echo Build completed successfully!
echo Executable created at: "%CD%\dist\YaraXGUI.exe"
goto finish

:try_python
if defined YARAXGUI_BUILD_PYTHON exit /b 0
rem Legacy Python launchers misparse a quoted extensionless command like "py".
rem Use an explicit .exe name and resolve its path before every invocation.
rem See https://github.com/python/cpython/issues/99442
set "YARAXGUI_BUILD_CANDIDATE=%~1"
if "%~x1"=="" set "YARAXGUI_BUILD_CANDIDATE=%~1.exe"
for %%P in ("%YARAXGUI_BUILD_CANDIDATE%") do if exist "%%~fP" set "YARAXGUI_BUILD_CANDIDATE=%%~fP"
for %%P in ("%YARAXGUI_BUILD_CANDIDATE%") do if not "%%~$PATH:P"=="" set "YARAXGUI_BUILD_CANDIDATE=%%~$PATH:P"
if defined YARAXGUI_BUILD_PROBE_VERBOSE goto probe_verbose
"%YARAXGUI_BUILD_CANDIDATE%" %~2 -c "import struct, sys; sys.exit(not (sys.version_info >= (3, 13) and struct.calcsize('P') == 8))" >nul 2>&1
goto probe_result

:probe_verbose
echo Checking requested interpreter: "%YARAXGUI_BUILD_CANDIDATE%" %~2
"%YARAXGUI_BUILD_CANDIDATE%" %~2 -c "import struct, sys; bits = struct.calcsize('P') * 8; print('Executable:', sys.executable); print('Version:', sys.version); print('Architecture:', bits, 'bit'); valid = sys.version_info >= (3, 13) and bits == 64; print('Interpreter check:', 'OK' if valid else 'Requires Python 3.13+ and a 64-bit interpreter'); sys.exit(0 if valid else 1)"

:probe_result
set "YARAXGUI_BUILD_PROBE_EXIT=%errorlevel%"
if not "%YARAXGUI_BUILD_PROBE_EXIT%"=="0" exit /b 1
set "YARAXGUI_BUILD_PYTHON=%YARAXGUI_BUILD_CANDIDATE%"
set "YARAXGUI_BUILD_PYTHON_ARGS=%~2"
exit /b 0

:python_error
set "YARAXGUI_BUILD_EXIT=9009"
if defined YARAXGUI_BUILD_PROBE_EXIT set "YARAXGUI_BUILD_EXIT=%YARAXGUI_BUILD_PROBE_EXIT%"
echo.
echo Could not run a 64-bit Python 3.13 or newer interpreter.
if defined YARAXGUI_BUILD_PROBE_VERBOSE echo The requested command failed with exit code %YARAXGUI_BUILD_EXIT%; see its output above.
echo List installed Python runtimes with: py --list
if defined VIRTUAL_ENV echo To use the active virtual environment instead, run: compile_to_exe.bat
echo Activate a working virtual environment or install Python with its launcher.
echo You can also supply the interpreter explicitly:
echo   compile_to_exe.bat py -3.13
echo   compile_to_exe.bat "C:\Path To Python\python.exe"
goto finish

:checkout_error
set "YARAXGUI_BUILD_EXIT=2"
echo.
echo Incomplete checkout: requirements.txt, packaging\yaraxgui.spec and
echo modules\yarax-editor\pyproject.toml must be present beside this script.
goto finish

:directory_error
echo Could not access the build script's directory.
goto finish

:dependency_error
echo.
echo Dependency install failed with error code %YARAXGUI_BUILD_EXIT%.
echo The previous executable has not been removed.
goto finish

:build_error
echo.
echo Build failed with error code %YARAXGUI_BUILD_EXIT%.
echo See the output above. If the executable is locked, close it and retry.

:finish
if defined YARAXGUI_BUILD_IN_ROOT popd
if not defined YARAXGUI_BUILD_NO_PAUSE pause
exit /b %YARAXGUI_BUILD_EXIT%
