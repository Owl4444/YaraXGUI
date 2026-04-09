@echo off
setlocal
set "PY=R:/YaraXGUI_Qt/YaraXGUI/.qtcreator/Python_3_13_7venv/Scripts/python.exe"

echo Cleaning up old build...
taskkill /f /im YaraXGUI.exe 2>nul
if exist "dist\YaraXGUI.exe" del /f "dist\YaraXGUI.exe" 2>nul
if exist "build" rmdir /s /q "build" 2>nul

echo Installing / refreshing dependencies...
"%PY%" -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo Dependency install failed with error code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo Building YaraXGUI executable...
"%PY%" -m PyInstaller yaraxgui.spec

if %errorlevel%==0 (
    echo.
    echo ✅ Build completed successfully!
    echo Executable created at: dist\YaraXGUI.exe
) else (
    echo.
    echo ❌ Build failed with error code %errorlevel%
)
pause