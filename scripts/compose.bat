@echo off
setlocal
rem Windows / Docker Desktop: persistent Docker storage, with explicit files.
pushd "%~dp0.."
if errorlevel 1 exit /b 1
docker compose --project-directory . -f compose.yaml -f deployment/compose.windows.yaml %*
set "YARAXGUI_COMPOSE_EXIT=%errorlevel%"
popd
exit /b %YARAXGUI_COMPOSE_EXIT%
